"""Mock process/journal tests; never contacts Proxmox or executes the payload."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cleanup', Path(__file__).with_name('proxmox-vm106-cleanup.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = Path(__file__).with_name('Complete-Worker106TailscaleCleanup.ps1')
        # Test the deployed LF bytes even from a CRLF Windows checkout.
        payload = self.root / 'payload.ps1'
        payload.write_bytes(self.payload.read_bytes().replace(b'\r\n', b'\n'))
        self.state = self.root / 'cleanup.json'
        for name, value in [('PAYLOAD', payload), ('STATE', self.state)]:
            context = patch.object(module, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.save_patch = patch.object(module, 'save', lambda record: self.state.write_text(json.dumps(record)))
        self.save_patch.start()
        self.addCleanup(self.save_patch.stop)
        for target, value in [('os.getuid', 0), ('sys.argv', ['cleanup'])]:
            context = patch.object(module.os, 'getuid', return_value=0, create=True) if target == 'os.getuid' else patch.object(module.sys, 'argv', value)
            context.start()
            self.addCleanup(context.stop)

    def test_success_is_retained_without_redispatch(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': True, 'exitcode': 0, 'out-data': '{}'}]) as qm:
            module.main()
            module.main()
            self.assertEqual(qm.call_count, 2)
            self.assertEqual(qm.call_args_list[1].args[0], ['guest', 'exec-status', '106', '42'])

    def test_launch_failure_is_never_retried(self):
        with patch.object(module, 'qm', side_effect=RuntimeError('transport')) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 1)

    def test_collection_failure_is_never_retried(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, RuntimeError('transport')]) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 2)

    def test_running_polls_same_pid(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': False}, {'exited': True, 'exitcode': 0}]) as qm:
            module.main()
            module.main()
            self.assertEqual(qm.call_count, 3)
            self.assertEqual(qm.call_args_list[1], qm.call_args_list[2])

    def test_failed_guest_retained(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': True, 'exitcode': 1}]) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 2)

    def test_wrong_payload_refused_before_launch(self):
        with patch.object(module, 'PAYLOAD_HASH', 'wrong'), patch.object(module, 'qm') as qm:
            with self.assertRaises(RuntimeError):
                module.main()
            qm.assert_not_called()


if __name__ == '__main__':
    unittest.main()
