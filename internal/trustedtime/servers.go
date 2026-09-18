package trustedtime

// NTSServers is the pinned list of NTS (RFC 8915) servers, one per operator,
// so any two picked at random come from different operators: national
// metrology institutes, internet exchanges, registries, universities and
// companies across Europe. Every entry passed an NTS-KE handshake (TLS 1.3,
// ALPN ntske/1, cookies returned) when it was chosen. Some refuse plain NTP,
// so a plain NTP probe is not a valid health check for them.
//
// The list is compiled into the measured manager on purpose, never read from
// configuration: whoever can change it can point the runtime at servers they
// run, and a valid certificate for a hostname one controls is easy to get.
// Changing it is a runtime roll.
//
// Backups that also passed the handshake, for when an entry has to be
// replaced: 1.nts.nothingtohide.nl, ntp.miuku.net,
// time.cincura.net, ntp01.maillink.ch.
var NTSServers = [...]string{
	"nts.netnod.se",           // Netnod (internet exchange), anycast, Sweden
	"ptbtime1.ptb.de",         // PTB (national metrology institute), Germany
	"nts.time.nl",             // TimeNL (SIDN, the .nl registry), Netherlands
	"time.cloudflare.com",     // Cloudflare, anycast, served from EU sites
	"ntp3.fau.de",             // FAU Erlangen-Nuernberg (university), Germany
	"ntp1.cam.ac.uk",          // University of Cambridge, UK
	"nts2.ntp.hr",             // University of Zagreb, FER, Croatia
	"paris.time.system76.com", // System76, France
	"ntp1.rdem-systems.com",   // RDEM Systems (Equinix Paris), France
	"nts.teambelgium.net",     // Team Belgium, Belgium
}
