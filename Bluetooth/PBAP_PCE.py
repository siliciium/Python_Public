"""
Copyright 2026 Silicium

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
"""

import sys,os,time,re,subprocess,gc,random,threading
from datetime import datetime
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib


class AutoAgent(dbus.service.Object):
	def __init__(self, bus, path):
		super().__init__(bus, path)

	@dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
	def Release(self):
		print(f"[AutoAgent] \u2192 Release")

	@dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="")
	def AuthorizeService(self, device, uuid):
		print(f"[AutoAgent] \u2192 AuthorizeService", device, uuid)
		return

	@dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="s")
	def RequestPinCode(self, device):
		pin = f"{random.randint(0, 999999):04d}"
		print(f"[AutoAgent] \u2192 RequestPinCode ({pin})", device)
		return pin

	@dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="u")
	def RequestPasskey(self, device):
		passkey = random.randint(0, 999999)
		print(f"[AutoAgent] \u2192 RequestPasskey ({passkey})", device)
		return dbus.UInt32(passkey)

	@dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
	def DisplayPasskey(self, device, passkey):
		print(f"[AutoAgent] \u2192 DisplayPasskey", device, passkey)
		pass
	# self.agent_capability = "DisplayYesNo"
	@dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
	def RequestConfirmation(self, device, passkey):
		print(f"[AutoAgent] \u2192 RequestConfirmation", device, passkey)
		return # auto-confirm

	@dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="")
	def RequestAuthorization(self, device):
		print(f"[AutoAgent] \u2192 RequestAuthorization", device, passkey)
		return

	@dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
	def Cancel(self):
		print(f"[AutoAgent] \u2192 Cancel", device)



class PBAP_PCE:
	def __init__(self, _location, _phonebook, _verbose=False):
		self.current_path = os.path.dirname(os.path.abspath(__file__))
		self.arrow="\u2192"

		self.uuids = {
			"Phonebook Access Server" : "0000112f-0000-1000-8000-00805f9b34fb"
		}

		self.phonebooks = {
			"phonebook" : "pb",
			"incoming calls history" : "ich",
			"outgoing calls history" : "och",
			"missed calls history"   : "mch",
			"combined calls history" : "cch",
		}

		self.search_is_mac = False
		self.search_filter = None
		self.uuid_filters = None

		self.location = _location
		self.phonebook = _phonebook
		self.verbose = _verbose
		self.current_dt = None
		self.out = None

		self.session_bus = None
		self.cli_interface = None
		self.session = None
		self.pba_interface = None
		self.loop = None
		self.transfer_path = None


		# commons
		self.system_bus = None
		# alias
		self.bt_interface = None
		self.props_interface_alias = None
		self.alias_loop = None
		# scan
		self.device = None
		self.adapter_interface = None
		self.omanager_interface = None
		self.scan_loop = None
		# pair, trust
		self.amanager_interface = None
		self.device_interface = None
		self.props_interface = None
		self.pair_loop = None
		self.trust_loop = None
		# agent
		self.use_autoagent = True
		self.agent = None
		self.agent_path = "/test/agent"
		self.agent_capability = "NoInputNoOutput"
		# DisplayOnly,DisplayYesNo,KeyboardOnly,NoInputNoOutput
		# DisplayYesNo :
		# - work on modern smartphone (SSP, take a bit more time ,ECDH, numeric compare on the two devices)
		# NoInputNoOutput :
		# - work on modern smartphone but some phones can failed (fast)


	def clean_after_alias(self):
		self.system_bus.remove_signal_receiver(
			self.on_properties_changed_alias,
			dbus_interface = "org.freedesktop.DBus.Properties",
			signal_name = "PropertiesChanged",
			path = self.bt_interface,
			path_keyword = "path"
		)
		del self.props_interface_alias
		del self.system_bus
		gc.collect()
		self.alias_loop.quit()
		return False

	def on_properties_changed_alias(self, interface, changed, invalidated, path):
		if interface != "org.bluez.Adapter1":
			return
		if 'Alias' in changed:
			if self.verbose:
				print(f"{self.arrow} Alias changed : {changed['Alias']}")
			GLib.idle_add(self.clean_after_alias)

	def changeAlias(self, bt_interface, bt_alias):
		if bt_interface is not None and bt_alias is not None:

			self.bt_interface = "/org/bluez/%s"%bt_interface

			dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

			if self.verbose:
				print(f"[+] Change {bt_interface} Alias ...")
			self.system_bus = dbus.SystemBus()
			self.props_interface_alias = dbus.Interface(
				self.system_bus.get_object("org.bluez", self.bt_interface),
				"org.freedesktop.DBus.Properties"
			)

			alias = self.props_interface_alias.Get("org.bluez.Adapter1", "Alias")
			if alias != bt_alias:
				self.system_bus.add_signal_receiver(
					self.on_properties_changed_alias,
					dbus_interface = "org.freedesktop.DBus.Properties",
					signal_name = "PropertiesChanged",
					path = self.bt_interface,
					path_keyword = "path"
				)

				self.alias_loop = GLib.MainLoop()
				self.props_interface_alias.Set("org.bluez.Adapter1", "Alias", bt_alias)
				try:
					self.alias_loop.run()
				except:
					pass
			else:
				del self.props_interface_alias
				del self.system_bus
				gc.collect()
				if self.verbose:
					print(f"{self.arrow} Alias is already set to : {alias}")


	def isMAC(self, val):
		MAC_REGEX = re.compile(r"^[0-9A-Fa-f]{2}[:]{1}[0-9A-Fa-f]{2}[:]{1}[0-9A-Fa-f]{2}[:]{1}[0-9A-Fa-f]{2}[:]{1}[0-9A-Fa-f]{2}[:]{1}[0-9A-Fa-f]{2}$")
		return bool(MAC_REGEX.match(val))

	def clean_after_search(self):
		self.adapter_interface.StopDiscovery()
		self.system_bus.remove_signal_receiver(
			self.on_device_found,
			dbus_interface = "org.freedesktop.DBus.ObjectManager",
			signal_name = "InterfacesAdded"
		)
		del self.omanager_interface
		del self.adapter_interface
		gc.collect()
		self.scan_loop.quit()
		if self.verbose:
			print(f"[+] Scan finished")

	def on_device_found(self, path, interfaces):
		if "org.bluez.Device1" in interfaces:
			props = interfaces['org.bluez.Device1']
			addr = props.get('Address')
			name = props.get('Name')
			if self.verbose:
				print(f"Found device: {addr} {name}")

			if (self.search_is_mac and (addr == self.search_filter)) or (not self.search_is_mac and (name == self.search_filter)):

				ok = False
				if len(self.uuid_filters) > 0:
					founds = []
					for uuid in self.uuid_filters:
						if uuid in props.get('UUIDs'):
							founds.append(True)
						else:
							founds.append(False)
					if not False in founds:
						ok = True
				else:
					ok = True


				if self.verbose:
					print(f"{self.arrow} device: {addr} {name}")
				self.device = { 'addr':addr, 'name':name, 'path':path, 'props':props}
				GLib.idle_add(self.clean_after_search)


	def do_pair(self):
		try:
			self.device_interface.Pair()
		except dbus.exceptions.DBusException as e:
			if 'NoReply' in str(e):
				# Normal, Bluez not respond to Pair()
				return False
			else:
				raise
		return False

	def clean_after_pair(self):
		self.system_bus.remove_signal_receiver(
			self.on_properties_changed_pair,
			dbus_interface = "org.freedesktop.DBus.Properties",
			signal_name = "PropertiesChanged",
			path_keyword = "path"
		)

		if self.use_autoagent:
			# agent
			self.amanager.UnregisterAgent(self.agent_path)
			del self.amanager
		# pair
		del self.device_interface
		gc.collect()

		self.pair_loop.quit()
		return False

	def on_properties_changed_pair(self, interface, changed, invalidated, path=None):
		if interface != "org.bluez.Device1":
			return
		if "Paired" in changed:
			if self.device['path'] == path:
				paired = changed['Paired']
				if self.verbose:
					print(f"{self.arrow} Pair : {paired}")
				GLib.idle_add(self.clean_after_pair)


	def clean_after_trust(self):
		self.system_bus.remove_signal_receiver(
			self.on_properties_changed_trust,
			dbus_interface = "org.freedesktop.DBus.Properties",
			signal_name = "PropertiesChanged",
			path_keyword = "path"
		)
		del self.props_interface
		gc.collect()
		self.trust_loop.quit()

	def on_properties_changed_trust(self, interface, changed, invalidated, path=None):
		if interface != "org.bluez.Device1":
			return
		if "Trusted" in changed:
			if self.device['path'] == path:
				trusted = changed['Trusted']
				if self.verbose:
					print(f"{self.arrow} Trust : {trusted}")
				GLib.idle_add(self.clean_after_trust)


	def Search(self, bt_addr_or_name, uuid_filters=[], auto_pair_trust=False):
		dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

		self.search_is_mac = self.isMAC(bt_addr_or_name)
		self.search_filter = bt_addr_or_name
		self.uuid_filters = uuid_filters

		self.system_bus = dbus.SystemBus()
		self.omanager_interface = dbus.Interface(
			self.system_bus.get_object("org.bluez", "/"),
			"org.freedesktop.DBus.ObjectManager"
		)
		self.objects = self.omanager_interface.GetManagedObjects()

		# device already known ?
		known_by_bluez = False

		if self.search_is_mac:
			mac_addr = self.search_filter.upper().replace(":", "_")

		for path, interfaces in self.objects.items():
			if "org.bluez.Device1" not in interfaces:
				continue
			else:
				props = interfaces['org.bluez.Device1']
				addr = props.get('Address')
				name = props.get('Name')

				if (self.search_is_mac and path.endswith(mac_addr)) or (not self.search_is_mac and (name == self.search_filter)):
					self.device = { 'addr':addr, 'name':name, 'path':path, 'props':props}

					known_by_bluez = True
					break

		if not known_by_bluez:
			self.adapter_path = None
			for path, interfaces in self.objects.items():
				if "org.bluez.Adapter1" in interfaces:
					self.adapter_path = path
					break

			self.adapter_interface = dbus.Interface(
				self.system_bus.get_object("org.bluez", self.adapter_path),
				"org.bluez.Adapter1"
			)

			self.system_bus.add_signal_receiver(
				self.on_device_found,
				dbus_interface = "org.freedesktop.DBus.ObjectManager",
				signal_name = "InterfacesAdded"
			)

			if self.verbose:
				print("[+] Scan started, please wait your device ...")

			self.scan_loop = GLib.MainLoop()
			self.adapter_interface.StartDiscovery()
			try:
				self.scan_loop.run()
			except:
				pass

		else:
			if self.verbose:
				print("[*] Device is known by bluez")


		if self.device is not None:
			if auto_pair_trust:
				if self.verbose:
					print(f"[*] Paired  : {self.device['props'].get('Paired')}")
					print(f"[*] Trusted : {self.device['props'].get('Trusted')}")

				if not self.device['props'].get('Paired'):

					if self.use_autoagent:
						self.agent = AutoAgent(self.system_bus, self.agent_path)
						self.amanager = dbus.Interface(
							self.system_bus.get_object("org.bluez", "/org/bluez"),
							"org.bluez.AgentManager1"
						)
						self.amanager.RegisterAgent(self.agent_path, self.agent_capability)
						self.amanager.RequestDefaultAgent(self.agent_path)


					if self.verbose:
						print(f"[+] Pairing with {self.device['addr']} ...")
					self.device_interface = dbus.Interface(
						self.system_bus.get_object("org.bluez", self.device['path']),
						"org.bluez.Device1"
					)
					self.system_bus.add_signal_receiver(
						self.on_properties_changed_pair,
						dbus_interface = "org.freedesktop.DBus.Properties",
						signal_name = "PropertiesChanged",
						path_keyword = "path"
					)


					self.pair_loop = GLib.MainLoop()

					threading.Thread(target=self.do_pair, daemon=True).start()

					if self.use_autoagent:
						if self.verbose:
							print(f"[+] Agent {self.agent_capability} (Default) actif")

					try:
						self.pair_loop.run()
					except:
						pass

				if not self.device['props'].get('Trusted'):
					if self.verbose:
						print(f"[+] Trusting {self.device['addr']} ...")
					self.props_interface = dbus.Interface(
						self.system_bus.get_object("org.bluez", self.device['path']),
						"org.freedesktop.DBus.Properties"
					)
					self.system_bus.add_signal_receiver(
						self.on_properties_changed_trust,
						dbus_interface = "org.freedesktop.DBus.Properties",
						signal_name = "PropertiesChanged",
						path_keyword = "path"
					)


					self.trust_loop = GLib.MainLoop()

					self.props_interface.Set("org.bluez.Device1", "Trusted", True)

					try:
						self.trust_loop.run()
					except:
						pass


		del self.system_bus
		gc.collect()

	def sanitize(self, name):
		return re.sub(r"[^A-Za-z_]", "_", name)

	def clean_after_transfer(self):
		# Clean disconnect
		self.cli_interface.RemoveSession(self.session)

		self.session_bus.remove_signal_receiver(
		    self.on_properties_changed,
		    signal_name="PropertiesChanged",
		    dbus_interface="org.freedesktop.DBus.Properties",
		    path=self.transfer_path,
		    path_keyword="path"
		)

		# session
		del self.session_bus
		del self.cli_interface
		del self.pba_interface
		gc.collect()

		self.loop.quit()

	def on_properties_changed(self, interface, changed, invalidated, path):
		if interface != "org.bluez.obex.Transfer1":
			return

		if "Status" in changed:
			if self.verbose:
				print(f"{self.arrow} [{path}] Status:", changed["Status"])

		if "Transferred" in changed:
			if self.verbose:
				print(f"{arrow} [{path}] Transferred:", changed["Transferred"])

		if "Size" in changed:
			if self.verbose:
				print(f"{self.arrow} [{path}] Size:", changed["Size"])

		# Fin du transfert
		if changed.get("Status") == "complete":
			if self.verbose:
				print(f"{self.arrow} [{path}] Transfert terminé.")

			if os.path.exists(self.targetfile):
				self.out = self.targetfile
			else:
				if self.verbose:
					print(f"{self.arrow} Error : missing {self.targetfile}")

			GLib.idle_add(self.clean_after_transfer)

	def Get(self, bt_addr, list=False, file=None):

		if file is not None:
			if not file.endswith(".vcf"):
				print(f"ERROR : {file} (must be file.vcf)")
				return

		now = datetime.now()
		self.current_dt = now.strftime("%Y-%m-%d_%H-%M-%S")

		dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

		self.session_bus = dbus.SessionBus()

		self.cli_interface = dbus.Interface(
			self.session_bus.get_object("org.bluez.obex", "/org/bluez/obex"),
			"org.bluez.obex.Client1"
		)

		# 1) Session PBAP
		try:
			self.session = self.cli_interface.CreateSession(
				bt_addr,
				{"Target": "PBAP"}
			)
			#print(self.session)
		except dbus.exceptions.DBusException as e:
			print(f"{self.arrow} ERROR: ",e)
			print(f"  On smarphone, ensure to check \"Allow phone book access\" before click associate")
			print(f"  If you need to restart, before do : bluetoothctl remove {bt_addr}")

			# session
			del self.session_bus
			del self.cli_interface
			gc.collect()

			sys.exit(1)

		# 3) Interface PBAP
		self.pba_interface = dbus.Interface(
			self.session_bus.get_object("org.bluez.obex", self.session),
			"org.bluez.obex.PhonebookAccess1"
		)

		# 4) Calls History / Contacts
		# gdbus introspect --session --dest org.bluez.obex --object-path /org/bluez/obex/client/session3
		if self.verbose:
			print(f"{self.arrow} Select {os.path.join(self.location, self.phonebook)}")

		self.pba_interface.Select(self.location, self.phonebook)


		if list:
			for e in self.pba_interface.List({}):
				print(e[0], e[1])

			return

		safe_devname = self.sanitize(self.device['name'])
		safe_location = self.location.replace("/", ".")

		if file is None:
			self.targetfile = f"{self.current_path}/transfers/{self.current_dt}.{safe_devname}.{safe_location}.{self.phonebook}.vcf"

			transfer, props = self.pba_interface.PullAll(self.targetfile, {})
			if self.verbose:
				print(f"{self.arrow} Pull started ...")
		else:
			self.targetfile = f"{self.current_path}/transfers/{self.current_dt}.{safe_devname}.{safe_location}.{self.phonebook}.{file}"
			transfer, props = self.pba_interface.Pull(file, self.targetfile, {})
			if self.verbose:
				print(f"{self.arrow} Pull started ...")

		self.transfer_path = transfer
		transfer_obj = self.session_bus.get_object("org.bluez.obex", self.transfer_path)

		self.session_bus.add_signal_receiver(
		    self.on_properties_changed,
		    signal_name="PropertiesChanged",
		    dbus_interface="org.freedesktop.DBus.Properties",
		    path=self.transfer_path,
		    path_keyword="path"
		)

		self.loop = GLib.MainLoop()
		self.loop.run()




if __name__ == '__main__':
	# dbus-send --print-reply --system --dest=org.bluez /org/bluez/hci1 org.freedesktop.DBus.Properties.Get string:"org.bluez.Adapter1" string:"Powered"

	hciX           = "hci?"
	local_bt_name  = "PBAP-PCE"
	remote_bt_name = "remote-bt-name"
	remote_bt_addr = "XX:XX:XX:XX:XX:XX"

	location       = "int" # int = telecom
	phonebook      = "pb"

	#location       = "SIM1/telecom"
	#phonebook      = "ich"

	pbap_pce = PBAP_PCE(location, phonebook, _verbose=True)

	#pbap_pce.changeAlias(hciX, local_bt_name)

	pbap_pce.Search(remote_bt_name, [pbap_pce.uuids['Phonebook Access Server']], auto_pair_trust=True)
	#print(pbap_pce.device)

	if pbap_pce.device is not None:
		#pbap_pce.Get(pbap_pce.device['addr'])
		#print(pbap_pce.out)

		pbap_pce.Get(pbap_pce.device['addr'], file="2.vcf")
		print(pbap_pce.out)

		#pbap_pce.Get(pbap_pce.device['addr'], list=True)

