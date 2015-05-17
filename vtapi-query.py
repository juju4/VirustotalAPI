#!/usr/bin/python
## basic script to query virustotal
##
## NEED: vtapi
## in: ip list as stdin or one ip argument
## out: input data; json virustotal output

import vtapi
import os, sys, time

import logging
import traceback
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", filename='debug.log',level=logging.DEBUG)
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", level=logging.DEBUG, stream=sys.stderr)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

w_network = 1
cef = 0
## Public API limit: max results 1000, Request rate	4 requests/minute
VTAPI_KEY = ''
VT_COUNT = 0

def virustotal_data(domain):
    global VTAPI_KEY
    global VT_COUNT
    if w_network == 1:
        try:
        	logger.debug("querying virustotal")
                vt = vtapi.VtApi(VTAPI_KEY, enable_cache=True)
                #vt = vtapi.VtApi(VTAPI_KEY, enable_cache=False)
                ret = vt.report(domain)
		if vt.last_cache_call != domain:
			VT_COUNT +=1
		return ret
        except Exception, e:
            return "VirusTotal: error " + str(e)
    else:
        return "Network call disabled"

# CEF Format -> CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
# Sample output CEF:0|VirusTotal|API|1.0|10000|Virustotal match|$severity|VTSCORE|VTURL
def vt2cef(vtret):
    vturl = vtresp = vtscore = vtsum = '' 
    severity = 0
    logging.debug("vtret is " + str(vtret))
    try: 
        if vtret != None:
            vturl = vtret["permalink"]
            vtres = vtret["resource"]
            vtresp = vtret["response_code"]
            if vtresp == 1:
                vtscore = str(vtret["positives"]) + '/' + str(vtret["total"])
            else:
                vtscore = 'Not scored'
            logging.debug("vtresp, vtscore: " + str(vtresp) + ', ' + str(vtscore))
            if vtret["positives"] > 10:
		severity = 2
                return "CEF:0|VirusTotal|API|1.0|10000|Virustotal match on " + str(vtres) + "|" + str(severity) + "|" + str(vtscore) + "|" + str(vturl)
            elif vtret["positives"] > 0:
		severity = 1
                return "CEF:0|VirusTotal|API|1.0|10000|Virustotal match on " + str(vtres) + "|" + str(severity) + "|" + str(vtscore) + "|" + str(vturl)
    except Exception, e:
        logging.error("Erreur virustotal for " + str(vtret) + ": " + str(e))

## either take stdin (one or multiple lines), either one argument
def main():
    global VT_COUNT
    try:
        if len(sys.argv) == 1:
            logger.debug("input as stdin")
            for line in sys.stdin:
                ## every 4req, sleep 1min to respect limitation
                if VT_COUNT != 0 and VT_COUNT % 4 == 0:
                    time.sleep(60)
                logging.debug("input line: " + line.strip())
		ret = virustotal_data(line.strip())
		if cef == 1 and ret is not None:
			retcef = vt2cef(ret)
			if retcef is not None:
				print retcef
	        elif cef == 0:
                    	print line.strip() + ';' + str(ret)
        elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
            logger.debug("input as file")
            with open(sys.argv[1], "r") as lines:
                for line in lines:
                    ## every 4req, sleep 1min to respect limitation
                    if VT_COUNT != 0 and VT_COUNT % 4 == 0:
                        time.sleep(60)
                    logging.debug("input line: " + line.strip())
		    ret = virustotal_data(line.strip())
		    if cef == 1 and ret is not None:
			retcef = vt2cef(ret)
			if retcef is not None:
				print retcef
	            elif cef == 0:
                    	print line.strip() + ';' + str(ret)
                    count += 1
        elif len(sys.argv) > 1:
            logger.debug("input as argument: " + sys.argv[1])
	    if cef == 1:
		print vt2cef(virustotal_data(sys.argv[1]))
	    else:
            	print virustotal_data(sys.argv[1])
        logger.debug("ending")
    
    except KeyboardInterrupt:
        print 'Goodbye Cruel World...'
        sys.exit(0)
    except Exception, error:
        traceback.print_exc()
        print '(Exception):, %s' % (str(error))
        sys.exit(1)

if __name__ == '__main__':
    main()
