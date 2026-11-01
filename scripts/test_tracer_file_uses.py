import copy
import json
from pathlib import Path
import unittest
import tracer_file_uses


class ConstructorInstallation(unittest.TestCase):
    def test_original_reset_window(self):
        fixture=json.loads((Path(__file__).resolve().parents[1]/'tracer/testdata/file-uses.json').read_text())
        base,key=fixture['report'],fixture['inventory']
        tracer_file_uses.validate(base,key)
        extra=copy.deepcopy(base)
        row=copy.deepcopy(extra['file_uses']['puts'][-1])
        row.update(page=999,input=dict(site='',source=None,kind='unbound',page=None,ok=False))
        extra['file_uses']['puts'].append(row)
        with self.assertRaisesRegex(ValueError,'unmatched installation'):tracer_file_uses.validate(extra,key)
        for path,value in [
            (('file_captures',1,'history_cursor'),4),
            (('puts',1,'input'),dict(source=1,site='file.goal_cases.build.001',kind='constructor',page=0,ok=True)),
            (('puts',1,'page'),8),
            (('puts',1,'at_ns'),13),
        ]:
            bad=copy.deepcopy(base)
            target=bad['file_uses']['puts'] if path[0]=='puts' else bad['file_captures']
            target[path[1]][path[2]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):tracer_file_uses.validate(bad,key)
        moved=copy.deepcopy(base)
        moved['file_captures'][1].update(history_cursor=4,at_ns=5)
        moved['file_uses']['puts'][1].update(history_cursor=4,at_ns=6)
        with self.assertRaises(ValueError):tracer_file_uses.validate(moved,key)
        missing=copy.deepcopy(base);missing['file_uses']['puts'].pop()
        with self.assertRaises(ValueError):tracer_file_uses.validate(missing,key)

    def test_original_operation_and_query_inputs(self):
        root=Path(__file__).resolve().parents[1]/'tracer/testdata'
        for name,controls in [
            ('file-operation-windows.json',[
                (('file_uses','operations',0,'session_source'),1),
                (('file_uses','operations',0,'end_ns'),23),
                (('file_captures',1,'at_ns'),21),
                (('file_uses','operations',0,'refused'),False),
                (('file_uses','operations',0,'worker'),4),
            ]),
            ('binding-operation-windows.json',[
                (('file_uses','binding',0,'end_ns'),14),
                (('reader_roots',0,'file_input','source'),4),
                (('file_uses','binding',1,'start_cursor'),5),
                (('file_uses','binding',0,'worker'),4),
                (('file_uses','binding',0,'ok'),False),
            ]),
        ]:
            fixture=json.loads((root/name).read_text());base,key=fixture['report'],fixture['inventory']
            tracer_file_uses.validate(base,key)
            for path,value in controls:
                bad=copy.deepcopy(base);node=bad
                for component in path[:-1]:node=node[component]
                node[path[-1]]=value
                with self.subTest(name=name,path=path),self.assertRaises(ValueError):tracer_file_uses.validate(bad,key)


if __name__=='__main__':unittest.main()
