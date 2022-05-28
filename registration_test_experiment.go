package test_test

import (
	//	"bytes"

	//	"encoding/binary"
	//	"encoding/hex"
	"fmt"
	//	"net"

	//	"os/exec"
	//	"strconv"
	"github.com/mohae/deepcopy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"test"
	"testing"
	"time"
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
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

const ranN2Ipv4Addr string = "127.0.0.1"
const amfN2Ipv4Addr string = "127.0.0.1"
const ranN3Ipv4Addr string = "10.100.200.1"
const upfN3Ipv4Addr string = "10.100.200.3"

const RegLog string = "[TEST][TestRegistration] "
const HandLog string = "[TEST][TestN2Handover] "

const colorCyan string = "\033[36m"
const colorReset string = "\033[0m"
const colorGreen string = "\033[32m"
const colorRed string = "\033[31m"

// Registration
func TestRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "RAN connect to AMF")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "RAN Connect To AMF Error", string(colorReset))
	}

	// RAN connect to UPF
	//	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	//	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGSetupRequest Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGSetupRequest Msg Error", string(colorReset))
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGSetupResponse Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGSetupResponse Msg Error", string(colorReset))
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2)
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
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Start Registration]", string(colorReset))
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send Initial UE Message")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send Initial UE Message Error", string(colorReset))
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NAS Authentication Request Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NAS Authentication Request Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Authentication Response")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Authentication Response Error", string(colorReset))
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NAS Security Mode Command Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NAS Security Mode Command Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

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
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Security Mode Complete Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Security Mode Complete Msg Error", string(colorReset))
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGAP Initial Context Setup Request Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGAP Initial Context Setup Request Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGAP Initial Context Setup Response Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGAP Initial Context Setup Response Msg Error", string(colorReset))
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
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Registration Complete Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Registration Complete Msg Error", string(colorReset))
	}

	t2 := time.Now()
	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Finish Registration]", string(colorReset), t2.Sub(t1).Seconds(), "(seconds)")

	time.Sleep(100 * time.Millisecond)

	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Start PDU Session Establishment]", string(colorReset))
	t3 := time.Now()

	// send GetPduSessionEstablishmentRequest Msg
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
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send PduSessionEstablishmentRequest Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send PduSessionEstablishmentRequest Msg Error", string(colorReset))
	}

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGAP-PDU Session Resource Setup Request")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGAP-PDU Session Resource Setup Request Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")
	fmt.Println(ngapPdu)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGAP-PDU Session Resource Setup Response")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGAP-PDU Session Resource Setup Response Error", string(colorReset))
	}

	t4 := time.Now()
	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Finish PDU Session Establishment]", string(colorReset), t4.Sub(t3).Seconds(), "(seconds)")

	// wait 1s
	time.Sleep(1 * time.Second)
	/*
		// Send the dummy packet
		// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
		gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
		assert.Nil(t, err)
		icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
		assert.Nil(t, err)

		ipv4hdr := ipv4.Header{
			Version:  4,
			Len:      20,
			Protocol: 1,
			Flags:    0,
			TotalLen: 48,
			TTL:      64,
			Src:      net.ParseIP("60.60.0.1").To4(),
			Dst:      net.ParseIP("60.60.0.101").To4(),
			ID:       1,
		}
		checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
		ipv4hdr.Checksum = int(checksum)

		v4HdrBuf, err := ipv4hdr.Marshal()
		assert.Nil(t, err)
		tt := append(gtpHdr, v4HdrBuf...)

		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: 12394, Seq: 1,
				Data: icmpData,
			},
		}
		b, err := m.Marshal(nil)
		assert.Nil(t, err)
		b[2] = 0xaf
		b[3] = 0x88
		_, err = upfConn.Write(append(tt, b...))
		assert.Nil(t, err)
	*/
	time.Sleep(1 * time.Second)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	//	NfTerminate()
}

// Registration -> PDU Session Establishment -> Source RAN Send Handover Required -> N2 Handover (Preparation Phase -> Execution Phase)
func TestN2Handover(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN1 connect to AMF
	conn, err := test.ConnectToAmf("127.0.0.1", "127.0.0.1", 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN1 Connect to AMF")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN1 Connect To AMF Error", string(colorReset))
	}

	/*	// RAN1 connect to UPF
		upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN1 send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x01"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN1 Send NGSetupRequest Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN1 Send NGSetupRequest Msg Error", string(colorReset))
	}

	// RAN1 receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN1 Receive NGSetupResponse Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN1 Receive NGSetupResponse Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// RAN2 connect to AMF
	conn2, err1 := test.ConnectToAmf("127.0.0.1", "127.0.0.1", 38412, 9488)
	assert.Nil(t, err1)
	if err1 == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN2 Connect to AMF")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN2 Connect To AMF Error", string(colorReset))
	}

	/*	// RAN2 connect to UPF
		upfConn2, err := test.ConnectToUpf("10.200.200.2", "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN2 send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN2 Send Second NGSetupRequest Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN2 Send Second NGSetupRequest Msg Error", string(colorReset))
	}

	// RAN2 receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "RAN2 Receive Second NGSetupResponse Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "RAN2 Receive Second NGSetupResponse Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300000001", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
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
		Len:    12,                                                                              // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, //4778
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Start Registration]", string(colorReset))
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send Initial UE Message")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send Initial UE Message Error", string(colorReset))
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Receive NAS Authentication Request Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Receive NAS Authentication Request Msg Error", string(colorReset))
	}
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send NAS Authentication Response")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send NAS Authentication Response Error", string(colorReset))
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Receive NAS Security Mode Command Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Receive NAS Security Mode Command Msg Error", string(colorReset))
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

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
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send NAS Security Mode Complete Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send NAS Security Mode Complete Msg Error", string(colorReset))
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Receive NGAP Initial Context Setup Request Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Receive NGAP Initial Context Setup Request Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send NGAP Initial Context Setup Response Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send NGAP Initial Context Setup Response Msg Error", string(colorReset))
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
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send NAS Registration Complete Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send NAS Registration Complete Msg Error", string(colorReset))
	}

	t2 := time.Now()
	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Finish Registration]", string(colorReset), t2.Sub(t1).Seconds(), "(seconds)")

	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Start PDU Session Establishment]", string(colorReset))
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
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Send PduSessionEstablishmentRequest Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Send PduSessionEstablishmentRequest Msg Error", string(colorReset))
	}

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Receive NGAP-PDU Session Resource Setup Request (DL NAS transport)")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Receive NGAP-PDU Session Resource Setup Request (DL NAS transport) Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Receive NGAP-PDU Session Resource Setup Request")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Receive NGAP-PDU Session Resource Setup Request Error", string(colorReset))
	}

	t4 := time.Now()
	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Finish PDU Session Establishment]", string(colorReset), t4.Sub(t3).Seconds(), "(seconds)")

	time.Sleep(1 * time.Second)

	/*	// Send the dummy packet to test if UE is connected to RAN1
		// ping IP(tunnel IP) from 60.60.0.1(127.0.0.1) to 60.60.0.100(127.0.0.8)
		gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
		assert.Nil(t, err)
		icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
		assert.Nil(t, err)

		ipv4hdr := ipv4.Header{
			Version:  4,
			Len:      20,
			Protocol: 1,
			Flags:    0,
			TotalLen: 48,
			TTL:      64,
			Src:      net.ParseIP("60.60.0.1").To4(),
			Dst:      net.ParseIP("60.60.0.101").To4(),
			ID:       1,
		}
		checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
		ipv4hdr.Checksum = int(checksum)

		v4HdrBuf, err := ipv4hdr.Marshal()
		assert.Nil(t, err)
		tt := append(gtpHdr, v4HdrBuf...)
		assert.Nil(t, err)

		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: 12394, Seq: 1,
				Data: icmpData,
			},
		}
		b, err := m.Marshal(nil)
		assert.Nil(t, err)
		b[2] = 0xaf
		b[3] = 0x88
		_, err = upfConn.Write(append(tt, b...))
		assert.Nil(t, err)
	*/
	time.Sleep(1 * time.Second)

	// ============================================

	// Source RAN send ngap Handover Required Msg
	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Start NGAP Handover]", string(colorReset))
	t5 := time.Now()

	sendMsg, err = test.GetHandoverRequired(ue.AmfUeNgapId, ue.RanUeNgapId, []byte{0x00, 0x01, 0x02}, []byte{0x01, 0x20})
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Source RAN Send NGAP Handover Required Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Source RAN Send NGAP Handover Required Msg Error", string(colorReset))
	}

	// Target RAN receive ngap Handover Request
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Receive NGAP Handover Request")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Receive NGAP Handover Request Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN create New UE
	targetUe := deepcopy.Copy(ue).(*test.RanUeContext)
	targetUe.AmfUeNgapId = 2
	targetUe.ULCount.Set(ue.ULCount.Overflow(), ue.ULCount.SQN())
	targetUe.DLCount.Set(ue.DLCount.Overflow(), ue.DLCount.SQN())

	// Target RAN send ngap Handover Request Acknowledge Msg
	sendMsg, err = test.GetHandoverRequestAcknowledge(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Send NGAP Handover Request Acknowledge Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Send NGAP Handover Request Acknowledge Msg Error", string(colorReset))
	}

	// End of Preparation phase
	time.Sleep(10 * time.Millisecond)

	// Beginning of Execution

	// Source RAN receive ngap Handover Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Source RAN Receive NGAP Handover Command")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Source RAN Receive NGAP Handover Command Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Handover Notify
	sendMsg, err = test.GetHandoverNotify(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Send NGAP Handover Notify")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Send NGAP Handover Notify Error", string(colorReset))
	}

	// Source RAN receive ngap UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Source RAN Receive NGAP UE Context Release Command")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Source RAN Receive NGAP UE Context Release Command Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Source RAN send ngap UE Context Release Complete
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Source RAN Send NGAP UE Context Release Complete")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Source RAN Send NGAP UE Context Release Complete Error", string(colorReset))
	}

	// UE send NAS Registration Request(Mobility Registration Update) To Target AMF (2 AMF scenario not supportted yet)
	mobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	uplinkDataStatus := nasType.NewUplinkDataStatus(nasMessage.RegistrationRequestUplinkDataStatusType)
	uplinkDataStatus.SetLen(2)
	uplinkDataStatus.SetPSI10(1)
	ueSecurityCapability = targetUe.GetUESecurityCapability()
	pdu = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, uplinkDataStatus)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(targetUe.RanUeNgapId, pdu, "")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "UE Send NAS Registration Request(Mobility Registration Update) To Target AMF Error", string(colorReset))
	}

	// Target RAN receive ngap Initial Context Setup Request Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Receive NGAP Initial Context Setup Request Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Receive NGAP Initial Context Setup Request Msg Error", string(colorReset))
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, "10.200.200.2")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Send NGAP Initial Context Setup Response Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Send NGAP Initial Context Setup Response Msg Error", string(colorReset))
	}

	// Target RAN send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), HandLog, string(colorReset), "Target RAN Send NAS Registration Complete Msg")
	} else {
		fmt.Println(string(colorCyan), HandLog, string(colorRed), "Target RAN Send NAS Registration Complete Msg Error", string(colorReset))
	}

	t6 := time.Now()
	fmt.Println(string(colorCyan), HandLog, string(colorGreen), "[Finish NGAP Handover]", string(colorReset), t6.Sub(t5).Seconds(), "(seconds)")

	// wait 1000 ms
	time.Sleep(1000 * time.Millisecond)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	//	_, err = upfConn2.Write(append(tt, b...))
	//	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
	conn2.Close()

	// terminate all NF
	//	NfTerminate()
}
