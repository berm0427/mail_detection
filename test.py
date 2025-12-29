import json
import sys

try:
    from konlpy.tag import Okt
    okt = Okt()
    
    text = sys.argv[1] if len(sys.argv) > 1 else ''
    pos = okt.pos(text)
    nouns = [w for w, t in pos if t in ['Noun', 'ProperNoun'] and len(w) >= 2]
    
    print(json.dumps(nouns[:20], ensure_ascii=False))

except Exception as e:
    import traceback
    error_info = {
        "error": str(e),
        "traceback": traceback.format_exc()
    }
    print(json.dumps(error_info, ensure_ascii=False))
    sys.exit(1)
