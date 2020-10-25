#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import asyncio
import aiohttp
import hashlib
import logging
import argparse

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s:\t%(message)s')

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 SE 2.X Metar 1.0"
}

class FingerEngine(object):
    def __init__(self, database='cmsprint.json'):
        self.dbfile = database
    
    # Load database into memory
    def loadDatabase(self):
        with open(self.dbfile, 'r') as db:
            self.database = json.loads(db.read())['RECORDS']

    async def _checkMd5(self, site, feature):
        if len(feature['staticurl']) == 0 and len(feature['checksum']) == 0:
            return False
        items = {
            "site": site,
            "staticurl": feature['staticurl']
        }
        url = "%(site)s%(staticurl)s" % items
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url) as resp:
                    if 200 == resp.status:
                        content = await resp.read()
                        checksum = hashlib.md5(content).hexdigest()
                        if feature['checksum'] == checksum:
                            return True
                        else:
                            return False
                    else:
                        return False
            except:
                return False

    async def _checkKeyword(self, site, feature):
        if len(feature['homeurl']) == 0 and len(feature['keyword']) == 0:
            return False
        items = {
            "site": site,
            "homeurl": feature['homeurl']
        }
        url = "%(site)s%(homeurl)s" % items
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url) as resp:
                    if 200 == resp.status:
                        content = await resp.text()
                        if content.find(feature['keyword']) >= 0:
                            #print(url, feature['keyword'])
                            return True
                        else:
                            return False
                    else:
                        return False
            except:
                return False

    async def run(self, site):
        result = set()
        for feature in self.database:
            keywordStatus = await self._checkKeyword(site, feature)
            checksumStatus = await self._checkMd5(site, feature)
            if keywordStatus or checksumStatus:
                result.add(feature['remark'])
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s','--site', type=str, help='target site url, start with http or https')
    parser.add_argument('-d','--database', type=str, default='cmsprint.json', help='database file, default is cmsprint.json')
    args = parser.parse_args()
    logger.info("[-]start engine.")
    if args.database == "cmsprint.json":
        engine = FingerEngine(database=args.database)
    else:
        engine = FingerEngine()
    logger.info('[-]loading database from %s.' % engine.dbfile)
    engine.loadDatabase()
    logger.info('[-]start finger print scan.')
    loop = asyncio.get_event_loop()
    feature = asyncio.ensure_future(engine.run(args.site))
    loop.run_until_complete(feature)
    for remark in feature.result():
        logger.info("\033[31m[+]fingerprint found: %s.\033[37m" % remark)
    logger.info('[-]task finished.')
    
        