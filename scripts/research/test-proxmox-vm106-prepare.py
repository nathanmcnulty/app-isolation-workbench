"""Credential-free closed dispatch and journal tests; no VM operations."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('proxmox-vm106-prepare.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        payload = self.root / 'payload.ps1'
        payload.write_bytes(Path(__file__).with_name('Prepare-Worker106Offline.ps1').read_bytes().replace(b'\r\n', b'\n'))
        contexts = [patch.object(module, 'PAYLOAD', payload), patch.object(module, 'STATE_ROOT', self.root),
                    patch.object(module.os, 'getuid', return_value=0, create=True),
                    patch.object(module.sys, 'argv', ['runner', 'Prepare']),
                    patch.object(module, 'save', lambda record: module.STATE.write_text(json.dumps(record)))]
        for context in contexts:
            context.start()
            self.addCleanup(context.stop)

    def test_fixed_launch_and_cached_result(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': 1, 'exitcode': 0}]) as qm:
            module.main()
            module.main()
            self.assertEqual(qm.call_count, 2)
            args = qm.call_args_list[0].args[0]
            self.assertIn('--pass-stdin', args)
            self.assertEqual(qm.call_args_list[0].kwargs['input_text'], module.PAYLOAD.read_text())
            command = base64.b64decode(args[-1]).decode('utf-16le')
            self.assertTrue(command.endswith('-Operation Prepare'))
            self.assertLess(len(command), 200)

    def test_unknown_operation_never_dispatches(self):
        for value in ['Prepare; whoami', 'cleanup', '../Prepare']:
            with patch.object(module.sys, 'argv', ['runner', value]), patch.object(module, 'qm') as qm:
                with self.assertRaises(RuntimeError):
                    module.main()
                qm.assert_not_called()

    def test_launch_failure_not_repeated(self):
        with patch.object(module, 'qm', side_effect=RuntimeError('transport')) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 1)

    def test_collection_failure_not_repeated(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, RuntimeError('transport')]) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 2)

    def test_verify_is_fresh_and_archived(self):
        with patch.object(module.sys, 'argv', ['runner', 'Verify']), patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': 1, 'exitcode': 0}, {'pid': 43}, {'exited': 1, 'exitcode': 0}]) as qm:
            module.main()
            module.main()
            self.assertEqual(qm.call_count, 4)
            self.assertEqual(len(list(self.root.glob('verify-*.json'))), 1)
            self.assertEqual(json.loads((self.root / 'verify.json').read_text())['pid'], 43)

    def test_failed_preparation_not_repeated(self):
        with patch.object(module, 'qm', side_effect=[{'pid': 42}, {'exited': 1, 'exitcode': 1}]) as qm:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    module.main()
            self.assertEqual(qm.call_count, 2)

    def test_wrong_payload_refused(self):
        with patch.object(module, 'PAYLOAD_HASH', 'wrong'), patch.object(module, 'qm') as qm:
            with self.assertRaises(RuntimeError):
                module.main()
            qm.assert_not_called()


if __name__ == '__main__':
    unittest.main()
