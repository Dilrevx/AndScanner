from pathlib import Path
from ..utils import rmf, execute
from .base import Extractor
from .archive import ArchiveExtractor


class OZipExtractor(Extractor):
    '''
    Ozip - OPPO package
    '''

    tool = Path(
        'romanalyzer_extractor/tools/oppo_ozip_decrypt/ozipdecrypt.py').absolute()

    def extract(self):
        '''
        run `tools/oppo_ozip_decrypt/ozipdecrypt.py` to convert ozip -> zip, then unarchive it

        return extracted path; None for err
        '''
        self.log.debug("OZip extract target: {}".format(self.target))
        self.log.debug("\tstart extract archive.")

        converted_zip = self.target.with_suffix('.zip')
        convert_cmd = 'python3 {decrypt_script} "{ozip}"'.format(
            decrypt_script=self.tool, ozip=self.target.absolute()
        )
        execute(convert_cmd)

        self.log.debug('\tconverted ozip to zip: {}'.format(converted_zip))

        extractor = ArchiveExtractor(converted_zip)
        self.extracted = extractor.extract()
        rmf(converted_zip)
        if self.extracted and self.extracted.exists():
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
        else:
            self.log.warn(
                "\tfailed to extract {} using unzip".format(converted_zip))
            return None
