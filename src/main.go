package selfCheck

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func selfCheck(name, birth, school, org, password string) (string, error) {
	usertoken, err := findUser(name, birth, school, org)
	if err != nil {
		return "", err
	}
	passwordtoken, err := validatePassword(password, org, usertoken)
	if err != nil {
		return "", err
	}
	grouptoken, userPNo, err := selectUserGroup(org, passwordtoken)
	if err != nil {
		return "", err
	}
	finaltoken, err := getUserInfo(userPNo, school, org, grouptoken)
	if err != nil {
		return "", err
	}
	res, err := registerServey(name, org, finaltoken)
	if err != nil {
		return "", err
	}
	return res, nil
}

var privateKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA81dCnCKt0NVH7j5Oh2+S
GgEU0aqi5u6sYXemouJWXOlZO3jqDsHYM1qfEjVvCOmeoMNFXYSXdNhflU7mjWP8
jWUmkYIQ8o3FGqMzsMTNxr+bAp0cULWu9eYmycjJwWIxxB7vUwvpEUNicgW7v5nC
wmF5HS33Hmn7yDzcfjfBs99K5xJEppHG0qc+q3YXxxPpwZNIRFn0Wtxt0Muh1U8a
vvWyw03uQ/wMBnzhwUC8T4G5NclLEWzOQExbQ4oDlZBv8BM/WxxuOyu0I8bDUDdu
tJOfREYRZBlazFHvRKNNQQD2qDfjRz484uFs7b5nykjaMB9k/EJAuHjJzGs9MMMW
tQIDAQAB
-----END PUBLIC KEY-----
`)

func encrypt(origData string) string {
	block, _ := pem.Decode(privateKey)
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pub := pubInterface.(*rsa.PublicKey)
	enc, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(origData))
	return base64.StdEncoding.EncodeToString(enc)
}

func findUser(name, birth, school, org string) (string, error) {

	val := map[string]string{
		"orgCode":   school,
		"loginType": "school",
		"stdntPNo":  "",
		"name":      encrypt(name),
		"birthday":  encrypt(birth),
	}

	jsonValue, _ := json.Marshal(val)

	req, _ := http.NewRequest("POST", "https://"+org+"hcs.eduro.go.kr/v2/findUser", bytes.NewBuffer(jsonValue))

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, _ := client.Do(req)

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var data map[string]string
	_ = json.Unmarshal(body, &data)

	usertoken := data["token"]

	return usertoken, nil
}

func validatePassword(password, org, token string) (string, error) {

	val := map[string]string{
		"deviceUuid": "",
		"password":   encrypt(password),
	}

	jsonValue, _ := json.Marshal(val)

	req, _ := http.NewRequest("POST", "https://"+org+"hcs.eduro.go.kr/v2/validatePassword", bytes.NewBuffer(jsonValue))

	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", token)

	client := &http.Client{}

	resp, _ := client.Do(req)

	defer resp.Body.Close()

	var resdata map[string]string

	body, _ := ioutil.ReadAll(resp.Body)

	_ = json.Unmarshal(body, &resdata)

	passwordtoken := strings.Replace(string(body), "\"", "", -1)

	return passwordtoken, nil
}

func selectUserGroup(org, token string) (string, string, error) {
	jsonValue, _ := json.Marshal("")
	req, _ := http.NewRequest("POST", "https://"+org+"hcs.eduro.go.kr/v2/selectUserGroup", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var data []map[string]string
	_ = json.Unmarshal(body, &data)

	userPNo := data[0]["userPNo"]
	grouptoken := data[0]["token"]

	return grouptoken, userPNo, nil
}

func getUserInfo(userPNo, orgCode, org, token string) (string, error) {
	val := map[string]string{
		"userPNo": userPNo,
		"orgCode": orgCode,
	}
	jsonValue, _ := json.Marshal(val)
	req, _ := http.NewRequest("POST", "https://"+org+"hcs.eduro.go.kr/v2/getUserInfo", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	// 'Content-Type': 'application/' + (method === 'GET' ? 'x-www-form-urlencoded' : 'json') + ';charset=UTF-8',
	// 'Accept': 'application/json, text/plain, */*',
	// 'Accept-Encoding': 'gzip, deflate, br',
	// 'Accept-Language': 'en-GB,en;q=0.9,ko-KR;q=0.8,ko;q=0.7,ja-JP;q=0.6,ja;q=0.5,zh-TW;q=0.4,zh;q=0.3,en-US;q=0.2',
	// 'Cache-Control': 'no-cache',
	// 'Connection': 'keep-alive',
	// 'Origin': 'https://hcs.eduro.go.kr',
	// 'Pragma': 'no-cache',
	// 'Referer': 'https://hcs.eduro.go.kr/',
	// 'Sec-Fetch-Dest': 'empty',
	// 'Sec-Fetch-Mode': 'cors',
	// 'Sec-Fetch-Site': 'same-site',
	// 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1',
	// 'X-Requested-With': 'XMLHttpRequest',

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var data map[string]string
	_ = json.Unmarshal(body, &data)
	finaltoken := data["token"]
	fmt.Println(string(finaltoken))
	return finaltoken, nil
}

func registerServey(name, org, token string) (string, error) {
	val := map[string]interface{}{
		"deviceUuid":         "",
		"rspns00":            "Y",
		"rspns01":            "1",
		"rspns02":            "1",
		"rspns03":            nil,
		"rspns04":            nil,
		"rspns05":            nil,
		"rspns06":            nil,
		"rspns07":            nil,
		"rspns08":            nil,
		"rspns09":            "0",
		"rspns10":            nil,
		"rspns11":            nil,
		"rspns12":            nil,
		"rspns13":            nil,
		"rspns14":            nil,
		"rspns15":            nil,
		"upperToken":         token,
		"upperUserNameEncpt": name,
	}
	jsonvalue, _ := json.Marshal(val)
	req, _ := http.NewRequest("POST", "https://"+org+"hcs.eduro.go.kr/registerServey", bytes.NewBuffer(jsonvalue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	client := &http.Client{}
	respon, _ := client.Do(req)
	defer respon.Body.Close()
	var resdata map[string]string
	body, _ := ioutil.ReadAll(respon.Body)
	_ = json.Unmarshal(body, &resdata)
	return resdata["inveYmd"], nil
}
