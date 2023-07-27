package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type Stats struct {
	Create   uint64
	Open     uint64
	Allocate uint64
	Release  uint64
	Read     uint64
	Write    uint64
	Lseek    uint64
	Flush    uint64
	Fsync    uint64
	FsyncDir uint64
	Rename   uint64
	Link     uint64
	Symlink  uint64
	Unlink   uint64
}

var stats Stats

func (s *Stats) snapshot() Stats {
	return Stats{
		Create:   atomic.LoadUint64(&stats.Create),
		Open:     atomic.LoadUint64(&stats.Open),
		Allocate: atomic.LoadUint64(&stats.Allocate),
		Release:  atomic.LoadUint64(&stats.Release),
		Read:     atomic.LoadUint64(&stats.Read),
		Write:    atomic.LoadUint64(&stats.Write),
		Lseek:    atomic.LoadUint64(&stats.Lseek),
		Flush:    atomic.LoadUint64(&stats.Flush),
		Fsync:    atomic.LoadUint64(&stats.Fsync),
		FsyncDir: atomic.LoadUint64(&stats.FsyncDir),
		Rename:   atomic.LoadUint64(&stats.Rename),
		Link:     atomic.LoadUint64(&stats.Link),
		Symlink:  atomic.LoadUint64(&stats.Symlink),
		Unlink:   atomic.LoadUint64(&stats.Unlink),
	}
}

func dumpStatsDiff(cur Stats, prv Stats) {
	glog.Info("stats:",
		" create=", cur.Create-prv.Create,
		" open=", cur.Open-prv.Open,
		" allocate=", cur.Allocate-prv.Allocate,
		" release=", cur.Release-prv.Release,
		" read=", cur.Read-prv.Read,
		" write=", cur.Write-prv.Write,
		" lseek=", cur.Lseek-prv.Lseek,
		" flush=", cur.Flush-prv.Flush,
		" fsync=", cur.Fsync-prv.Fsync,
		" fsyncdir=", cur.FsyncDir-prv.FsyncDir,
		" rename=", cur.Rename-prv.Rename,
		" link=", cur.Link-prv.Link,
		" symlink=", cur.Symlink-prv.Symlink,
		" unlink=", cur.Unlink-prv.Unlink,
	)
}

type Regexp struct {
	*regexp.Regexp
}

func (r *Regexp) UnmarshalText(b []byte) error {
	regex, err := regexp.Compile(string(b))
	if err != nil {
		return err
	}
	r.Regexp = regex
	return nil
}

func (r *Regexp) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}
	return nil, nil
}

type Injector interface {
	fmt.Stringer
	Hit(path string) bool
	Done() bool
	Next() uint64
	Eval() syscall.Errno
}

type BaseInjector struct {
	Prob  float64 `json:"prob"`
	Count uint64  `json:"count"`
	Match *Regexp `json:"match,omitempty"`
}

func (inj *BaseInjector) Hit(path string) bool {
	if inj.Match == nil || (len(path) > 0 && inj.Match.MatchString(path)) {
		return rand.Float64() < inj.Prob
	}
	return false
}

func (inj *BaseInjector) String() string {
	return fmt.Sprintf("base{prob=%f,match=%s}", inj.Prob, inj.Match)
}

func (inj *BaseInjector) Done() bool {
	return atomic.LoadUint64(&inj.Count) == 0
}

func (inj *BaseInjector) Next() uint64 {
	for {
		count := atomic.LoadUint64(&inj.Count)
		if count == 0 {
			return 0
		}
		if atomic.CompareAndSwapUint64(&inj.Count, count, count-1) {
			return count
		}
	}
}

func (inj *BaseInjector) Eval() syscall.Errno {
	return fs.OK
}

type ErrorInjector struct {
	BaseInjector `json:",inline"`
	Errno        uint `json:"errno"`
}

func (inj *ErrorInjector) String() string {
	return fmt.Sprintf("error{prob=%f,match=%s,errno=%d}", inj.Prob, inj.Match, inj.Errno)
}

func (inj *ErrorInjector) Eval() syscall.Errno {
	return syscall.Errno(inj.Errno)
}

type DelayInjector struct {
	BaseInjector `json:",inline"`
	Mean         float64 `json:"mean"`
	StdDev       float64 `json:"stddev,omitempty"`
}

func (inj *DelayInjector) String() string {
	return fmt.Sprintf("delay{prob=%f,match=%s,mean=%f,stddev=%f}", inj.Prob, inj.Match, inj.Mean, inj.StdDev)
}

func (inj *DelayInjector) Eval() syscall.Errno {
	dur := inj.Mean
	if inj.StdDev > 0 {
		dur += inj.StdDev * rand.NormFloat64()
	}
	if dur > 0 {
		time.Sleep(time.Duration(dur * float64(time.Second)))
	}
	return fs.OK
}

type InjectorList struct {
	sync.RWMutex
	Name  string
	Items []Injector
}

func (lst *InjectorList) Append(inj Injector) {
	lst.Lock()
	lst.Items = append(lst.Items, inj)
	lst.Unlock()
}

func (lst *InjectorList) Clear() {
	lst.Lock()
	lst.Items = lst.Items[:0]
	lst.Unlock()
}

func (lst *InjectorList) Show() []string {
	lst.RLock()
	defer lst.RUnlock()
	arr := make([]string, len(lst.Items))
	for i, inj := range lst.Items {
		arr[i] = inj.String()
	}
	return arr
}

func (lst *InjectorList) Inject(path string) (syscall.Errno, bool) {
	clr := false
	defer func() {
		if clr {
			lst.Lock()
			defer lst.Unlock()
			idx := 0
			for _, inj := range lst.Items {
				if inj.Done() {
					glog.Infof("[%s] remove exhausted injector: %s", lst.Name, inj)
					continue
				}
				lst.Items[idx] = inj
				idx++
			}
			lst.Items = lst.Items[:idx]
		}
	}()
	lst.RLock()
	defer lst.RUnlock()
	for _, inj := range lst.Items {
		if inj.Hit(path) {
			cur := inj.Next()
			if cur <= 1 {
				clr = true
			}
			if cur > 0 {
				glog.V(2).Info("[", lst.Name, "] inject ", inj)
				return inj.Eval(), true
			}
		}
	}
	return fs.OK, false
}

var chaos = map[string]*InjectorList{
	"create":   {Name: "create"},
	"open":     {Name: "open"},
	"allocate": {Name: "allocate"},
	"release":  {Name: "release"},
	"read":     {Name: "read"},
	"write":    {Name: "write"},
	"flush":    {Name: "flush"},
	"fsync":    {Name: "fsync"},
	"fsyncdir": {Name: "fsyncdir"},
	"rename":   {Name: "rename"},
	"link":     {Name: "link"},
	"unlink":   {Name: "unlink"},
}

func handleChaosRequest(w http.ResponseWriter, r *http.Request) {
	// POST /{failpoint}/{injector}
	if r.Method == http.MethodPost {
		dir, name := path.Split(r.URL.Path)
		op := path.Base(dir)
		lst := chaos[op]
		if lst == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var (
			inj Injector
			err error
		)
		switch name {
		case "delay":
			var impl DelayInjector
			err = json.NewDecoder(r.Body).Decode(&impl)
			inj = &impl
		case "error":
			var impl ErrorInjector
			err = json.NewDecoder(r.Body).Decode(&impl)
			inj = &impl
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		lst.Append(inj)
		w.WriteHeader(http.StatusOK)
		glog.Info("[", op, "] append injector: ", inj)
		return
	}

	// DELETE /*
	op := path.Base(r.URL.Path)
	if op == "*" && r.Method == http.MethodDelete {
		for _, lst := range chaos {
			lst.Clear()
		}
		w.WriteHeader(http.StatusOK)
		glog.Info("clear all injectors")
		return
	}

	// GET|DELETE /{failpoint}
	lst := chaos[op]
	if lst == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		info := lst.Show()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(info)
		return
	} else if r.Method == http.MethodDelete {
		lst.Clear()
		w.WriteHeader(http.StatusOK)
		glog.Info("[", op, "] clear injectors")
		return
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

type HookNode struct {
	fs.LoopbackNode
}

func newHookNode(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
	return &HookNode{LoopbackNode: fs.LoopbackNode{RootData: rootData}}
}

func (n *HookNode) path() string {
	return filepath.Join(n.RootData.Path, n.Path(n.Root()))
}

var _ fs.NodeCreater = (*HookNode)(nil)

func (n *HookNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	atomic.AddUint64(&stats.Create, 1)
	path := filepath.Join(n.path(), name)
	if err, ok := chaos["create"].Inject(path); ok && err != fs.OK {
		return nil, nil, 0, err
	}
	node, fh, fuseFlags, errno := n.LoopbackNode.Create(ctx, name, flags, mode, out)
	return node, &HookFileHandle{fh, path}, fuseFlags, errno
}

var _ fs.NodeOpener = (*HookNode)(nil)

func (n *HookNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	atomic.AddUint64(&stats.Open, 1)
	path := n.path()
	if err, ok := chaos["open"].Inject(path); ok && err != fs.OK {
		return nil, 0, err
	}
	fh, fuseFlags, errno := n.LoopbackNode.Open(ctx, flags)
	return &HookFileHandle{fh, path}, fuseFlags, errno
}

var _ fs.NodeFsyncer = (*HookNode)(nil)

func (n *HookNode) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	if f == nil {
		atomic.AddUint64(&stats.FsyncDir, 1)
		path := n.path()
		if err, ok := chaos["fsyncdir"].Inject(path); ok && err != fs.OK {
			return err
		}
		fd, err := syscall.Open(n.path(), syscall.O_DIRECTORY, 0755)
		if err != nil {
			return fs.ToErrno(err)
		}
		defer syscall.Close(fd)
		if err := syscall.Fsync(fd); err != nil {
			return fs.ToErrno(err)
		}
		return fs.OK
	} else {
		if fs, ok := f.(fs.FileFsyncer); ok {
			return fs.Fsync(ctx, flags)
		}
		return syscall.ENOTSUP
	}
}

var _ fs.NodeRenamer = (*HookNode)(nil)

func (n *HookNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	atomic.AddUint64(&stats.Rename, 1)
	if err, ok := chaos["rename"].Inject(filepath.Join(n.path(), name)); ok && err != fs.OK {
		return err
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

var _ fs.NodeLinker = (*HookNode)(nil)

func (n *HookNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	atomic.AddUint64(&stats.Link, 1)
	if err, ok := chaos["link"].Inject(filepath.Join(n.path(), name)); ok && err != fs.OK {
		return nil, err
	}
	return n.LoopbackNode.Link(ctx, target, name, out)
}

var _ fs.NodeUnlinker = (*HookNode)(nil)

func (n *HookNode) Unlink(ctx context.Context, name string) syscall.Errno {
	atomic.AddUint64(&stats.Unlink, 1)
	if err, ok := chaos["unlink"].Inject(filepath.Join(n.path(), name)); ok && err != fs.OK {
		return err
	}
	return n.LoopbackNode.Unlink(ctx, name)
}

var _ fs.NodeSymlinker = (*HookNode)(nil)

func (n *HookNode) Symlink(ctx context.Context, target string, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	atomic.AddUint64(&stats.Symlink, 1)
	return n.LoopbackNode.Symlink(ctx, target, name, out)
}

type HookFileHandle struct {
	fs.FileHandle
	path string
}

var _ fs.FileAllocater = (*HookFileHandle)(nil)

func (h *HookFileHandle) Allocate(ctx context.Context, off uint64, sz uint64, mode uint32) syscall.Errno {
	atomic.AddUint64(&stats.Allocate, 1)
	if err, ok := chaos["allocate"].Inject(h.path); ok && err != fs.OK {
		return err
	}
	if fh, ok := h.FileHandle.(fs.FileAllocater); ok {
		return fh.Allocate(ctx, off, sz, mode)
	}
	glog.Warningf("inner file handle %T does not support `allocate`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileReleaser = (*HookFileHandle)(nil)

func (h *HookFileHandle) Release(ctx context.Context) syscall.Errno {
	atomic.AddUint64(&stats.Release, 1)
	if err, ok := chaos["release"].Inject(h.path); ok && err != fs.OK {
		return err
	}
	if fh, ok := h.FileHandle.(fs.FileReleaser); ok {
		return fh.Release(ctx)
	}
	glog.Warningf("inner file handle %T does not support `release`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileReader = (*HookFileHandle)(nil)

func (h *HookFileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	atomic.AddUint64(&stats.Read, 1)
	if err, ok := chaos["read"].Inject(h.path); ok && err != fs.OK {
		return nil, err
	}
	if fh, ok := h.FileHandle.(fs.FileReader); ok {
		return fh.Read(ctx, dest, off)
	}
	glog.Warningf("inner file handle %T does not support `read`", h.FileHandle)
	return nil, syscall.ENOTSUP
}

var _ fs.FileWriter = (*HookFileHandle)(nil)

func (h *HookFileHandle) Write(ctx context.Context, data []byte, off int64) (written uint32, errno syscall.Errno) {
	atomic.AddUint64(&stats.Write, 1)
	if err, ok := chaos["write"].Inject(h.path); ok && err != fs.OK {
		return 0, err
	}
	if fh, ok := h.FileHandle.(fs.FileWriter); ok {
		return fh.Write(ctx, data, off)
	}
	glog.Warningf("inner file handle %T does not support `write`", h.FileHandle)
	return 0, syscall.ENOTSUP
}

var _ fs.FileFlusher = (*HookFileHandle)(nil)

func (h *HookFileHandle) Flush(ctx context.Context) syscall.Errno {
	atomic.AddUint64(&stats.Flush, 1)
	if err, ok := chaos["flush"].Inject(h.path); ok && err != fs.OK {
		return err
	}
	if fh, ok := h.FileHandle.(fs.FileFlusher); ok {
		return fh.Flush(ctx)
	}
	glog.Warningf("inner file handle %T does not support `flush`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileFsyncer = (*HookFileHandle)(nil)

func (h *HookFileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	atomic.AddUint64(&stats.Fsync, 1)
	if err, ok := chaos["fsync"].Inject(h.path); ok && err != fs.OK {
		return err
	}
	if fh, ok := h.FileHandle.(fs.FileFsyncer); ok {
		return fh.Fsync(ctx, flags)
	}
	glog.Warningf("inner file handle %T does not support `fsync`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileLseeker = (*HookFileHandle)(nil)

func (h *HookFileHandle) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	atomic.AddUint64(&stats.Lseek, 1)
	if fh, ok := h.FileHandle.(fs.FileLseeker); ok {
		return fh.Lseek(ctx, off, whence)
	}
	glog.Warningf("inner file handle %T does not support `lseek`", h.FileHandle)
	return 0, syscall.ENOTSUP
}

var _ fs.FileGetattrer = (*HookFileHandle)(nil)

func (h *HookFileHandle) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if fh, ok := h.FileHandle.(fs.FileGetattrer); ok {
		return fh.Getattr(ctx, out)
	}
	glog.Warningf("inner file handle %T does not support `getattr`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileSetattrer = (*HookFileHandle)(nil)

func (h *HookFileHandle) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if fh, ok := h.FileHandle.(fs.FileSetattrer); ok {
		return fh.Setattr(ctx, in, out)
	}
	glog.Warningf("inner file handle %T does not support `setattr`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileGetlker = (*HookFileHandle)(nil)

func (h *HookFileHandle) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if fh, ok := h.FileHandle.(fs.FileGetlker); ok {
		return fh.Getlk(ctx, owner, lk, flags, out)
	}
	glog.Warningf("inner file handle %T does not support `getlk`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileSetlker = (*HookFileHandle)(nil)

func (h *HookFileHandle) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if fh, ok := h.FileHandle.(fs.FileSetlker); ok {
		return fh.Setlk(ctx, owner, lk, flags)
	}
	glog.Warningf("inner file handle %T does not support `setlk`", h.FileHandle)
	return syscall.ENOTSUP
}

var _ fs.FileSetlkwer = (*HookFileHandle)(nil)

func (h *HookFileHandle) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if fh, ok := h.FileHandle.(fs.FileSetlkwer); ok {
		return fh.Setlkw(ctx, owner, lk, flags)
	}
	glog.Warningf("inner file handle %T does not support `setlkw`", h.FileHandle)
	return syscall.ENOTSUP
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	debug := flag.Bool("debug", false, "print debugging messages")
	other := flag.Bool("allow-other", false, "mount with allow_other")
	readonly := flag.Bool("read-only", false, "mount read-only")
	directmount := flag.Bool("directmount", false, "try to call the mount syscall instead of executing fusermount")
	directmountstrict := flag.Bool("directmountstrict", false, "like directmount, but don't fall back to fusermount")
	reportInterval := flag.Duration("report-interval", 10*time.Second, "report stats every interval")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Printf("USAGE: %s [OPTIONS] MOUNTPOINT ORIGINAL\n", path.Base(os.Args[0]))
		fmt.Printf("\nOPTIONS:\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	mnt, orig := flag.Arg(0), flag.Arg(1)
	timeout := time.Second
	opts := &fs.Options{
		// The timeout options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		AttrTimeout:  &timeout,
		EntryTimeout: &timeout,

		NullPermissions: true, // Leave file permissions on "000" files as-is

		MountOptions: fuse.MountOptions{
			AllowOther:        *other,
			Debug:             *debug,
			DirectMount:       *directmount,
			DirectMountStrict: *directmountstrict,
			FsName:            orig,     // 1st column in "df -T": original dir
			Name:              "hookfs", // 2nd column in "df -T" will be shown as "fuse." + Name
		},
	}
	if opts.AllowOther {
		// Make the kernel check file permissions for us
		opts.MountOptions.Options = append(opts.MountOptions.Options, "default_permissions")
	}
	if *readonly {
		opts.MountOptions.Options = append(opts.MountOptions.Options, "ro")
	}

	server, err := fs.Mount(mnt, &HookNode{LoopbackNode: fs.LoopbackNode{RootData: &fs.LoopbackRoot{NewNode: newHookNode, Path: orig}}}, opts)
	if err != nil {
		glog.Fatalf("mount failed: %v", err)
	}
	glog.Infof("mounted: %s -> %s", orig, mnt)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Unmount()
	}()
	go func() {
		http.HandleFunc("/chaos/", handleChaosRequest)
		glog.Fatal(http.ListenAndServe(*addr, nil))
	}()
	if *reportInterval > 0 {
		go func() {
			var (
				cur Stats
				prv Stats
			)
			for range time.Tick(*reportInterval) {
				cur = stats.snapshot()
				dumpStatsDiff(cur, prv)
				prv = cur
			}
		}()
	}
	server.Wait()
}
