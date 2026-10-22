"""No credentials or VM operations: management transition and custody tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('management', Path(__file__).with_name('proxmox-vm106-management.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        payload = self.root / 'payload.ps1'
        payload.write_bytes(Path(__file__).with_name('Enable-Worker106Management.ps1').read_bytes().replace(b'\r\n', b'\n'))
        contexts = [patch.object(module, 'ROOT', self.root), patch.object(module, 'PAYLOAD', payload),
                    patch.object(module.os, 'getuid', return_value=0, create=True),
                    patch.object(module.sys, 'argv', ['runner', 'Bootstrap']),
                    patch.object(module, 'save', lambda path, record: path.write_text(json.dumps(record)))]
        for context in contexts:
            context.start()
            self.addCleanup(context.stop)
        self.guard = {'phase': 'finished', 'started': time.time(), 'freshly_collected': True, 'result': {'out-data': json.dumps({
            'Phase': 'Guarded', 'Result': 'firewallGuardedBeforeNetwork',
            'VmUuid': '7e686bee-8c05-43c7-9603-a9562ece224c', 'Controller': '192.168.1.165',
            'AdminSid': 'S-1-5-21-3849540285-1795134874-2442050430-1006'})}}

    def test_pending_guard_prevents_network(self):
        with patch.object(module, 'guest', return_value={'phase': 'running'}), patch.object(module, 'enable_network') as network:
            module.main()
            network.assert_not_called()

    def test_wrong_guard_prevents_network(self):
        observed = json.loads(self.guard['result']['out-data'])
        for field in ('Phase', 'Result', 'VmUuid', 'Controller', 'AdminSid'):
            invalid = dict(observed, **{field: 'wrong'})
            with patch.object(module, 'qm') as qm:
                with self.assertRaises(RuntimeError):
                    module.enable_network({'result': {'out-data': json.dumps(invalid)}})
                qm.assert_not_called()

    def test_exact_network_toggle_and_readback(self):
        with patch.object(module, 'qm', side_effect=['net0: ' + module.OFFLINE_NET, '', 'net0: ' + module.MANAGEMENT_NET]) as qm:
            module.enable_network(self.guard)
            self.assertEqual(qm.call_args_list[1].args[0], ['set', '106', '--net0', module.MANAGEMENT_NET])
            self.assertEqual(json.loads((self.root / 'management-network.json').read_text())['phase'], 'enabled')

    def test_network_intent_recovers_without_repeating_toggle(self):
        (self.root / 'management-network.json').write_text(json.dumps({'phase': 'intent', 'payload': module.PAYLOAD_HASH}))
        with patch.object(module, 'qm', return_value='net0: ' + module.MANAGEMENT_NET) as qm:
            module.enable_network(self.guard)
            self.assertEqual(qm.call_count, 2)
            self.assertFalse(any(call.args[0][0] == 'set' for call in qm.call_args_list))

    def test_unexpected_nic_is_never_changed(self):
        with patch.object(module, 'qm', return_value='net0: wrong') as qm:
            with self.assertRaises(RuntimeError):
                module.enable_network(self.guard)
            self.assertEqual(qm.call_count, 1)

    def test_cached_guard_never_authorizes_first_activation(self):
        self.guard.pop('freshly_collected')
        with patch.object(module, 'qm') as qm:
            with self.assertRaises(RuntimeError):
                module.enable_network(self.guard)
            qm.assert_not_called()

    def test_disconnect_cannot_be_undone_by_cached_bootstrap(self):
        (self.root / 'management-network.json').write_text(json.dumps({'phase': 'enabled', 'payload': module.PAYLOAD_HASH}))
        with patch.object(module, 'qm', return_value='net0: ' + module.OFFLINE_NET) as qm:
            with self.assertRaises(RuntimeError):
                module.enable_network(self.guard)
            self.assertEqual(qm.call_count, 1)

    def test_delayed_guard_collection_cannot_activate_network(self):
        self.guard['started'] = time.time() - 3600
        with patch.object(module, 'qm') as qm:
            with self.assertRaises(RuntimeError):
                module.enable_network(self.guard)
            qm.assert_not_called()

    def test_launch_failure_not_repeated(self):
        with patch.object(module, 'qm', side_effect=RuntimeError('transport')) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.guest('Guard')
            self.assertEqual(qm.call_count, 1)

    def test_collection_failure_not_repeated(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, RuntimeError('transport')]) as qm:
            self.assertEqual(module.guest('Guard')['phase'], 'running')
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.guest('Guard')
            self.assertEqual(qm.call_count, 2)

    def test_info_never_enables_network(self):
        with patch.object(module.sys, 'argv', ['runner', 'Info']), patch.object(module, 'guest', return_value={'phase': 'running'}) as guest, patch.object(module, 'enable_network') as network:
            module.main()
            guest.assert_called_once_with('Info')
            network.assert_not_called()

    def test_wrong_hash_never_dispatches(self):
        with patch.object(module, 'PAYLOAD_HASH', 'wrong'), patch.object(module, 'guest') as guest:
            with self.assertRaises(RuntimeError):
                module.main()
            guest.assert_not_called()


if __name__ == '__main__':
    unittest.main()
