package launcher

// ResourceDecl is a user-owned resource an app declares in its measured
// manifest (P1 of plans/drive-as-remote-disk.md), forwarded by the control
// plane in the load request. The runtime owns the consent flow that turns a
// declaration into a grant (P2); until that lands the declaration is
// recorded on the container spec and nothing is served for it.
type ResourceDecl struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
	Mount       string   `json:"mount,omitempty"`

	// Options are the declaration's options, verbatim, for kinds that take
	// some (app_storage: quota, unattended). The wallet phrases them.
	Options map[string]any `json:"options,omitempty"`

	// ResourceApp is the app id of the service that will mint this
	// capability, stamped by the CONTROL PLANE and never read from the app's
	// own manifest.
	//
	// It arrives here rather than being looked up because this is a generic
	// runtime: which product serves "mail.mailbox" on which fleet is not
	// something an operating system should know, and a table of product app
	// ids compiled into it would have to be edited and re-rolled for every
	// connector anyone ever ships.
	//
	// Never the app's to supply: an app that could name its own resource
	// service could point the holder at one it controls, and the consent
	// screen would look identical. The control plane strips any value the
	// manifest carried before stamping its own.
	ResourceApp string `json:"resource_app,omitempty"`
}

// ContainerResourceDecls returns the resources a loaded container declared
// in its manifest (a copy; nil when it declared none).
func (l *Launcher) ContainerResourceDecls(name string) []ResourceDecl {
	l.mu.RLock()
	defer l.mu.RUnlock()
	decls := l.resourceDecls[name]
	if len(decls) == 0 {
		return nil
	}
	return append([]ResourceDecl(nil), decls...)
}

// SetTaskPreStart installs f to run for every new container task after its
// namespaces exist and before it starts (container.Manager.SetPreStart).
// The manager calls it before Run has created the container manager, so the
// hook is kept and applied when Run attaches it (attachContainerManager);
// installing it only on an existing container manager silently dropped it
// on 146-dev.
//
// f runs INSIDE a load, under the launcher's lock (l.mu): it must never call
// the launcher (that deadlocked 147-dev), and it must return in bounded
// time. An error from f keeps the task from starting, so the load fails.
func (l *Launcher) SetTaskPreStart(f func(name string, pid int) error) {
	l.mu.Lock()
	l.taskPreStart = f
	mgr := l.mgr
	l.mu.Unlock()
	if mgr != nil {
		mgr.SetPreStart(f)
	}
}

// ContainerTaskPID is the init PID of the container's running task, or
// false when it has none. The manager reads the container's own mount view
// through /proc/<pid>/mountinfo with it.
func (l *Launcher) ContainerTaskPID(name string) (int, bool) {
	mc, ok := l.mgr.Get(name)
	if !ok || mc.Task == nil {
		return 0, false
	}
	pid := int(mc.Task.Pid())
	return pid, pid > 0
}

// ContainerHostname returns the public hostname a loaded container serves
// on, or "" when unknown.
func (l *Launcher) ContainerHostname(name string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.specs[name].Hostname
}
