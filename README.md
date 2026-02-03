# IG-EXTCAP

Wireshark extcap provider for connecting to the [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget)
[tcpdump gadget](https://inspektor-gadget.io/docs/latest/gadgets/tcpdump).

This requires a running installation of Inspektor Gadget (>=v0.47) either as Kubernetes Daemonset or in daemon mode (using
`ig daemon`).

## Installation

Start Wireshark and go to its "About" dialog. Under the "folders" tab look for "Personal Extcap path" and copy the
ig-extcap binary file for your specific platform there.

## Usage

After restarting Wireshark, it should show you two new interfaces in the interface selection:

![Interfaces](docs/interfaces.png)

* Inspektor Gadget (Daemon): use this, if you're running `ig daemon`
* Inspektor Gadget on Kubernetes: use this, if you're running ig installed on your Kubernetes cluster

When using "Inspektor Gadget (Daemon)", make sure the remote address is configured correctly (matching the daemon
configuration).

Click the "cog" icon left to the interface name to open the configuration dialog.

### Filters

You can apply filters to capture traffic only on matching containers:

![K8s Filtering](docs/options_k8s_filters.png)

### Gadget Configuration

![Gadget Options](docs/options_gadget.png)

#### Gadget Image

Here you can specify a gadget OCI image to use for capturing. Doesn't usually need to be changed.

#### SnapLen

Limits the number of bytes that should be captured from each packet. This can massively reduce the network traffic.

## Adding IG Lua dissector

Again, look at the folders in Wireshark's "About" dialog and navigate to the "Personal Lua Plugins" folder. Place the
dissector file in there and restart Wireshark. You should be able to see additional data when capturing traffic using
Inspektor Gadget.

![Dissector Preview](docs/dissector.png)

If you want to add this information as a column to the upper packet list, you can do so by:

* right clicking the header -> "Column Preferences"
* click "+" at the bottom
* choose a "Title", set "Type" to "Custom" and as "Custom Expression" use any of (auto-completion should be available 
  after capturing):
  * ig.k8s.containerName
  * ig.k8s.ns
  * ig.k8s.pod
  * ig.proc.comm
  * ig.runtime.containerName

![Columns](docs/columns.png)