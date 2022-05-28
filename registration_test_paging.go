package test_test

import (
	//	"bytes"

	//	"encoding/binary"
	//	"encoding/hex"
	"fmt"
	//	"net"

	"os/exec"
	//	"strconv"
	"test"
	"testing"
	"time"

	//	"github.com/mohae/deepcopy"
	"github.com/stretchr/testify/assert"
	//	"github.com/stretchr/testify/require"
	//	"golang.org/x/net/icmp"
	//	"golang.org/x/net/ipv4"

	// ausf_context "github.com/free5gc/ausf/context"
	"github.com/free5gc/CommonConsumerTestData/UDM/TestGenAuthData"
	//	"github.com/free5gc/milenage"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasTestpacket"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	//	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	//"github.com/ishidawataru/sctp"
	//	"git.cs.nctu.edu.tw/calee/sctp"
	//	"strings"
	//	"sync"
)

const ranN2Ipv4Addr string = "127.0.0.1"
const amfN2Ipv4Addr string = "127.0.0.1"
const ranN3Ipv4Addr string = "10.100.200.1"
const upfN3Ipv4Addr string = "10.100.200.3"

const PageLog string = "[TEST][TestPaging] "

const colorCyan string = "\033[36m"
const colorReset string = "\033[0m"
const colorGreen string = "\033[32m"
const colorRed string = "\033[31m"
const colorYellow string = "\033[33m"

// Registration -> Pdu Session Establishment -> AN Release due to UE Idle -> Send downlink data
func TestPaging(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(ranN2Ipv4Addr, amfN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "RAN connect to AMF")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "RAN Connect To AMF Error", string(colorReset))
	}

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NGSetupRequest Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NGSetupRequest Msg Error", string(colorReset))
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive NGSetupResponse Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive NGSetupResponse Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Start Registration]", string(colorReset))
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send Initial UE Message")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send Initial UE Message Error", string(colorReset))
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive NAS Authentication Request Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive NAS Authentication Request Msg Error", string(colorReset))
	}
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	assert.NotNil(t, nasPdu)
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NAS Authentication Response")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NAS Authentication Response Error", string(colorReset))
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive NAS Security Mode Command Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive NAS Security Mode Command Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NAS Security Mode Complete Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NAS Security Mode Complete Msg Error", string(colorReset))
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive NGAP Initial Context Setup Request Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive NGAP Initial Context Setup Request Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NGAP Initial Context Setup Response Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NGAP Initial Context Setup Response Msg Error", string(colorReset))
	}

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NAS Registration Complete Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NAS Registration Complete Msg Error", string(colorReset))
	}

	t2 := time.Now()
	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Finish Registration]", string(colorReset), t2.Sub(t1).Seconds(), "(seconds)")

	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Start PDU Session Establishment]", string(colorReset))
	t3 := time.Now()

	// send PduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send PduSessionEstablishmentRequest Msg")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send PduSessionEstablishmentRequest Msg Error", string(colorReset))
	}

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive NGAP-PDU Session Resource Setup Request")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive NGAP-PDU Session Resource Setup Request Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NGAP-PDU Session Resource Setup Response")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NGAP-PDU Session Resource Setup Response Error", string(colorReset))
	}

	t4 := time.Now()
	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Finish PDU Session Establishment]", string(colorReset), t4.Sub(t3).Seconds(), "(seconds)")

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NGAP UE Context Release Request")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NGAP UE Context Release Request Error", string(colorReset))
	}

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive UE Context Release Command")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive UE Context Release Command Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NGAP UE Context Release Complete")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NGAP UE Context Release Complete Error", string(colorReset))
	}

	// UE is CM-IDLE now
	fmt.Println(string(colorCyan), PageLog, string(colorYellow), "[UE IS CM-IDLE NOW]", string(colorReset))
	time.Sleep(1 * time.Second)
	fmt.Println(string(colorCyan), PageLog, string(colorYellow), "[Instruct DN To Send Downlink Traffic]", string(colorReset))

	// send downlink data
	// go func() {
	// 	// RAN connect to UPF
	// 	upfConn, err := test.ConnectToUpf(ranIpAddr, "10.200.200.102", 2152, 2152)
	// 	assert.Nil(t, err)
	// 	_, _ = upfConn.Read(recvMsg)
	// 	// fmt.Println(string(recvMsg))
	// }()

	// cmd := exec.Command("sudo", "ip", "netns", "exec", "UPFns", "bash", "-c", "echo -n 'hello' | nc -u -w1 60.60.0.1 8080")

	cmd := exec.Command("python3", "../../test-script3.0.5/python_client.py")
	_, err = cmd.Output()
	if err != nil {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Instruct DN to send downlink traffic Error:", string(colorReset), err)
		assert.Nil(t, err)
	}

	time.Sleep(1 * time.Second)

	fmt.Println(string(colorCyan), PageLog, string(colorYellow), "[Waiting To Receive Paing From AMF]", string(colorReset))
	// receive paing from AMF
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive paing from AMF")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive paing from AMF Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Start Paging]", string(colorReset))
	t5 := time.Now()

	// send NAS Service Request
	pdu = nasTestpacket.GetServiceRequest(nasMessage.ServiceTypeMobileTerminatedServices)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send NAS Service Request")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send NAS Service Request Error", string(colorReset))
	}

	// receive Initial Context Setup Request
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Receive Initial Context Setup Request")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Receive Initial Context Setup Request Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	//send Initial Context Setup Response
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), PageLog, string(colorReset), "Send Initial Context Setup Response")
	} else {
		fmt.Println(string(colorCyan), PageLog, string(colorRed), "Send Initial Context Setup Response Error", string(colorReset))
	}

	t6 := time.Now()
	fmt.Println(string(colorCyan), PageLog, string(colorGreen), "[Finish Paging]", string(colorReset), t6.Sub(t5).Seconds(), "(seconds)")

	time.Sleep(1 * time.Second)
	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
}
