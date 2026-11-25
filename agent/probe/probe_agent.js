// tlsLibHunter `discover --probe` agent (source; bundled into
// tlslibhunter/discovery/probe_agent.js by `npm run build` in this folder).
//
// Reports, once each:
//   {type: "binder", descriptor}  - binder interfaces the app calls (BinderProxy.transact)
//   {type: "net", port, proto}    - outgoing TLS sockets (TCP 443/853, UDP/QUIC 443), once per fd+port
// Every hook is wrapped in try/catch: a failed hook must never crash the target.
import Java from "frida-java-bridge";

const MAX_DESCRIPTORS = 500;
const MAX_NET_EVENTS = 200;
// IBinder.INTERFACE_TRANSACTION ('_NTF'): getInterfaceDescriptor() itself.
const INTERFACE_TRANSACTION = 0x5f4e5446;
const AF_INET = 2;
const AF_INET6 = 10;
const TCP_PORTS = [443, 853];
const UDP_PORTS = [443];

const seenDescriptors = new Set();
const describedProxies = new Set();
const seenSockets = new Set();

function reportDescriptor(descriptor) {
  if (!descriptor || seenDescriptors.has(descriptor) || seenDescriptors.size >= MAX_DESCRIPTORS) return;
  seenDescriptors.add(descriptor);
  send({ type: "binder", descriptor: descriptor });
}

function describeProxy(proxy, identity) {
  if (describedProxies.has(identity)) return;
  describedProxies.add(identity);
  try {
    const descriptor = proxy.getInterfaceDescriptor();
    reportDescriptor(descriptor === null ? null : descriptor.toString());
  } catch (e) {
    // dead object / RemoteException: nothing to report
  }
}

function hookBinderProxy() {
  const BinderProxy = Java.use("android.os.BinderProxy");
  const System = Java.use("java.lang.System");
  const transact = BinderProxy.transact.overload("int", "android.os.Parcel", "android.os.Parcel", "int");
  transact.implementation = function (code, data, reply, flags) {
    if (code !== INTERFACE_TRANSACTION) {
      try {
        describeProxy(this, System.identityHashCode(this));
      } catch (e) {
        // never break the app's binder call
      }
    }
    return transact.call(this, code, data, reply, flags);
  };
}

function installJavaHooks() {
  if (!Java.available) return;
  Java.perform(function () {
    try {
      hookBinderProxy();
    } catch (e) {
      send({ type: "error", where: "binder", message: String(e) });
    }
  });
}

const SOL_SOCKET = 1;
const SO_TYPE = 3;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
let getsockopt = null;

function socketProto(fd) {
  if (getsockopt === null) return null;
  const value = Memory.alloc(4);
  const length = Memory.alloc(4);
  length.writeU32(4);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, value, length) !== 0) return null;
  const type = value.readU32() & 0xf;
  if (type === SOCK_STREAM) return "tcp";
  if (type === SOCK_DGRAM) return "udp";
  return null;
}

function portsFor(proto) {
  return proto === "tcp" ? TCP_PORTS : proto === "udp" ? UDP_PORTS : [];
}

function readSockaddr(addr) {
  if (addr.isNull()) return null;
  const family = addr.readU16();
  if (family !== AF_INET && family !== AF_INET6) return null;
  const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
  return { family: family, port: port };
}

function reportSocket(fd, sockaddr) {
  try {
    const peer = readSockaddr(sockaddr);
    if (peer === null) return;
    const proto = socketProto(fd);
    if (portsFor(proto).indexOf(peer.port) < 0) return;
    const key = fd + ":" + peer.port + ":" + proto;
    if (seenSockets.has(key) || seenSockets.size >= MAX_NET_EVENTS) return;
    seenSockets.add(key);
    send({ type: "net", port: peer.port, proto: proto });
  } catch (e) {
    // unreadable sockaddr: ignore
  }
}

function libcExport(name) {
  try {
    return Process.getModuleByName("libc.so").findExportByName(name);
  } catch (e) {
    return null;
  }
}

function hookExport(name, callbacks) {
  const address = libcExport(name);
  if (address === null) return;
  try {
    Interceptor.attach(address, callbacks);
  } catch (e) {
    send({ type: "error", where: name, message: String(e) });
  }
}

function bindGetsockopt() {
  const address = libcExport("getsockopt");
  if (address === null) return;
  try {
    getsockopt = new NativeFunction(address, "int", ["int", "int", "int", "pointer", "pointer"]);
  } catch (e) {
    getsockopt = null;
  }
}

function installNativeHooks() {
  bindGetsockopt();
  hookExport("connect", {
    onEnter(args) {
      reportSocket(args[0].toInt32(), args[1]);
    },
  });
  hookExport("sendto", {
    onEnter(args) {
      reportSocket(args[0].toInt32(), args[4]);
    },
  });
}

installNativeHooks();
installJavaHooks();
