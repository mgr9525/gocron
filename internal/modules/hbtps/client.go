package hbtps

import (
	"context"
	"fmt"
	hbtp "github.com/mgr9525/HyperByte-Transfer-Protocol"
	ruisUtil "github.com/mgr9525/go-ruisutil"
	"github.com/ouqiang/gocron/internal/models"
	"os"
	"strings"
	"time"
)

func Exec(host string, port int, m *models.HbtpRequest) (string, error) {
	var req *hbtp.Request
	ishbp := strings.HasPrefix(host, "hbproxy:")
	hosts := strings.Replace(host, "hbproxy:", "", 1)
	if ishbp {
		conn, err := HbproxyConn(hosts, port, nil)
		if err != nil {
			return "", err
		}
		req = hbtp.NewConnRequest(conn, 1, time.Second*5)
	} else {
		req = hbtp.NewRequest(fmt.Sprintf("%s:%d", hosts, port), 1, time.Second*5)
	}
	secrets := os.Getenv("GOCRON_RUIS_SECRET")
	times := time.Now().Format(time.RFC3339Nano)
	random := ruisUtil.RandomString(20)
	req.SetArg("times", times)
	req.SetArg("random", random)
	signs := ruisUtil.Md5String(secrets + random + times + AllHbtpMD5Token)
	req.SetArg("sign", signs)
	req.SetVersion(2)
	res, err := req.Do(context.TODO(), m)
	if err != nil {
		return "", err
	}
	defer res.Close()
	conts := string(res.BodyBytes())
	if res.Code() != hbtp.ResStatusOk {
		return "", fmt.Errorf("hbtp do err(%d):%s", res.Code(), conts)
	}
	return conts, nil
}
