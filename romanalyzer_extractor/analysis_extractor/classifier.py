from pathlib import Path
from ..utils import log, execute


def magic_guess(target, mime=False) -> str:
    '''
    wrapper for linux call `file`. 
    Return a long description i.e. Python script, ASCII text executable
    '''
    cmd = 'file "{}"'.format(target)
    if mime:
        cmd += ' --mime-type'
    output = execute(cmd, showlog=False)
    return output.split(':', 1)[-1].strip() if output else ''


ARCHIVE_EXT = ('.gz', '.tgz', '.bz2', '.xz', '.tar',
               '.zip', '.rar', '.7z', '.md5', '.APP')
INTERESTING_EXT = ('.ko', '.so', '.dex', '.odex', '.apk', '.jar', '.ozip')


def AttributeClassifier(target):
    '''
    dir / symlink
    '''
    if target.is_dir():
        return 'dir'
    if target.is_symlink():
        return 'symlink'


def ExtensionClassifier(target: Path):
    '''
    ko, so, dex, odex, apk, jar, ozip
    '''
    return target.suffix.strip('.') if target.suffix in INTERESTING_EXT else ''


TextSigMap = {
    'ELF': 'elf',
    'ASCII': 'text',
    'Android bootimg': 'bootimg',
    'Android sparse image': 'sparseimg',
    'ext4 filesystem': 'extimg'
}


def TextSigClassifier(target):
    '''
    elf, text, bootimg, sparseimg, extimg
    '''
    for key in TextSigMap.keys():
        if key in magic_guess(target):
            return TextSigMap[key]


def ArchiveClassifier(target):
    '''
    archive extension, i.e. zip, APP

    Returns:
        'archive'
    '''
    if target.suffix in ARCHIVE_EXT or \
            magic_guess(target, mime=True) == 'application/zip':
        return 'archive'


def NewDatBrClassifier(target) -> str:
    '''
    new.dat or new.dat.br(brotli)
    '''

    if target.name.endswith('.new.dat'):
        return 'newdat'
    if target.name.endswith('.new.dat.br'):
        return 'brotli'


def SpecialDataClassifier(target):
    '''
    used when `file` returns 'data'

    return 'otapayload' if name *is* payload.bin; dataimg for .img,.bin;otherwise data
    '''
    if magic_guess(target) != 'data':
        return ''
    if target.name == 'payload.bin':
        return 'otapayload'
    return 'dataimg' if target.suffix in ('.img', '.bin') else 'data'


classify_queue = [
    AttributeClassifier,
    NewDatBrClassifier,
    ExtensionClassifier,
    ArchiveClassifier,
    SpecialDataClassifier,
    TextSigClassifier,
]


def Classify(target) -> str:
    '''
    Identify `target` file type based on filename

    May return: dir, symlink, newdat, so, apk, zip, dataimg, data, text, bootimg
    '''
    target = Path(target)
    if not target.exists():
        log.warn("Not exists: {}".format(target))
        return ''

    for classifier in classify_queue:
        result = classifier(target)
        if result:
            return result

    return 'unknown'
