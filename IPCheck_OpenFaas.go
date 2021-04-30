package function

import (
	"os/exec"
	"strings"
	"sync"
)

func Handle(req []byte) string {
	//ip := string(req)
	ip := "8.8.8.8"
	return checkIpBlackList(ip)

}

func checkIpBlackList(ip string) string {
	RBLList := []string{
		"aspews.ext.sorbs.net",
		"b.barracudacentral.org",
		"bl.deadbeef.com",
		"bl.emailbasura.org",
		"bl.spamcannibal.org",
		"bl.spamcop.net",
		"blackholes.five-ten-sg.com",
		"blacklist.woody.ch",
		"bogons.cymru.com",
		"cbl.abuseat.org",
		"cdl.anti-spam.org.cn",
		"combined.abuse.ch",
		"combined.rbl.msrbl.net",
		"db.wpbl.info",
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"dnsbl.cyberlogic.net",
		"dnsbl.dronebl.org",
		"dnsbl.inps.de",
		"dnsbl.justspam.org",
		"dnsbl.njabl.org",
		"dnsbl.sorbs.net",
		"dnsbl.spfbl.net",
		"drone.abuse.ch",
		"duinv.aupads.org",
		"dul.dnsbl.sorbs.net",
		"dul.ru",
		"dyna.spamrats.com",
		"dynip.rothen.com",
		"http.dnsbl.sorbs.net",
		"images.rbl.msrbl.net",
		"ips.backscatterer.org",
		"ix.dnsbl.manitu.net",
		"korea.services.net",
		"misc.dnsbl.sorbs.net",
		"noptr.spamrats.com",
		"ohps.dnsbl.net.au",
		"omrs.dnsbl.net.au",
		"orvedb.aupads.org",
		"osps.dnsbl.net.au",
		"osrs.dnsbl.net.au",
		"owfs.dnsbl.net.au",
		"owps.dnsbl.net.au",
		"pbl.spamhaus.org",
		"phishing.rbl.msrbl.net",
		"probes.dnsbl.net.au",
		"proxy.bl.gweep.ca",
		"proxy.block.transip.nl",
		"psbl.surriel.com",
		"rdts.dnsbl.net.au",
		"relays.bl.gweep.ca",
		"relays.bl.kundenserver.de",
		"relays.nether.net",
		"residential.block.transip.nl",
		"ricn.dnsbl.net.au",
		"rmst.dnsbl.net.au",
		"sbl.spamhaus.org",
		"short.rbl.jp",
		"smtp.dnsbl.sorbs.net",
		"socks.dnsbl.sorbs.net",
		"spam.abuse.ch",
		"spam.dnsbl.sorbs.net",
		"spam.rbl.msrbl.net",
		"spam.spamrats.com",
		"spamlist.or.kr",
		"spamrbl.imp.ch",
		"t3direct.dnsbl.net.au",
		"tor.dnsbl.sectoor.de",
		"torserver.tor.dnsbl.sectoor.de",
		"ubl.lashback.com",
		"ubl.unsubscore.com",
		"virbl.bit.nl",
		"virus.rbl.jp",
		"virus.rbl.msrbl.net",
		"web.dnsbl.sorbs.net",
		"wormrbl.imp.ch",
		"xbl.spamhaus.org",
		"zen.spamhaus.org",
		"zombie.dnsbl.sorbs.net"}

	splitAddress := strings.Split(ip, ".")
	for i, j := 0, len(splitAddress)-1; i < len(splitAddress)/2; i, j = i+1, j-1 {
		splitAddress[i], splitAddress[j] = splitAddress[j], splitAddress[i]
	}
	ip = strings.Join(splitAddress, ".")

	result := false
	var mux sync.Mutex
	wg := sync.WaitGroup{}
	for _, dnsServer := range RBLList {
		if result {
			break
		}
		wg.Add(1)
		go func(ds string) {
			bytes, e := exec.Command("nslookup", ip+"."+ds).Output()
			if e != nil {
				mux.Lock()
				result = result || false
				mux.Unlock()
				wg.Done()
				return
			}
			mux.Lock()
			result = result || strings.Contains(string(bytes), "127.0.0.")
			mux.Unlock()
			wg.Done()
		}(dnsServer)
	}
	wg.Wait()

	str := "Bu ip blacklistlere takılmamıştır"
	if result {
		str = "Bu ip blacklistlere takılmıştır"
	}
	return str
}
