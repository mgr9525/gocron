package utils

import (
	"fmt"
	ruisUtil "github.com/mgr9525/go-ruisutil"
	"net"
	"strconv"
	"strings"
	"time"

	hbtp "github.com/mgr9525/HyperByte-Transfer-Protocol"
)

type hbproxyGoto struct {
	ProxyHost string  `json:"proxy_host"`
	ProxyPort int     `json:"proxy_port"`
	Localhost *string `json:"localhost"`
}
type hbproxyInfo struct {
	Proxys []*hbproxyGoto `json:"proxys"`
	Limit  *ProxyLimit    `json:"limit"`
}
type ProxyLimit struct {
	Up   uint32 `json:"up"`
	Down uint32 `json:"down"`
}

func HbproxyConn(node string, port int, lmt *ProxyLimit, locals ...string) (net.Conn, error) {
	req := hbtp.NewRequest("localhost:6574", 2, time.Second*5)
	req.Command("NodeProxy")
	req.SetVersion(2)
	ifo := &hbproxyInfo{Limit: lmt}
	var lcs *string = nil
	if len(locals) > 0 && locals[0] != "" {
		lcs = &locals[0]
	}
	ifo.Proxys = append(ifo.Proxys, &hbproxyGoto{
		ProxyHost: node,
		ProxyPort: port,
		Localhost: lcs,
	})
	res, err := req.Do(nil, ifo)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.Code() != hbtp.ResStatusOk {
		return nil, fmt.Errorf("hbtp res err:code=%d,errs=%s", res.Code(), string(res.BodyBytes()))
	}
	return res.Conn(true), nil
}

func HbproxyConns(proxyHost string, lmt *ProxyLimit, locals ...string) (net.Conn, error) {
	prxs := strings.Split(proxyHost, ":")
	if len(prxs) != 2 || prxs[0] == "" {
		return nil, fmt.Errorf("proxy host:port err")
	}
	port, err := strconv.Atoi(prxs[1])
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("proxy port err:%v", err)
	}
	return HbproxyConn(prxs[0], port, lmt, locals...)
}

var AllHbtpMD5Token = "ETJFGQ5KLSJFXXYW5QVRIBU0BNNYDTNM"

func AllHbtpAuthCheck(c *hbtp.Context) bool {
	secrets := c.Args().Get("secrets")
	times := c.Args().Get("times")
	random := c.Args().Get("random")
	sign := c.Args().Get("sign")

	signs := ruisUtil.Md5String(secrets + random + times + AllHbtpMD5Token)
	if sign != signs {
		// println("sign err:" + sign)
		c.ResString(hbtp.ResStatusAuth, "sign err:"+sign)
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, times)
	if err != nil {
		c.ResString(hbtp.ResStatusAuth, "times err:"+err.Error())
		return false
	}
	//println(fmt.Sprintf("authCheck [%s] parse.times:%s", c.Command(), tms.Format(comm.TimeFmt)))
	return true
}
