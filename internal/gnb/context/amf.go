/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package context

import (
	"fmt"
	"net/netip"

	"github.com/free5gc/aper"
	"github.com/ishidawataru/sctp"
)

const (
	Inactive = 0x00
	Active   = 0x01
	Overload = 0x02
)

type GNBElla struct {
	ellaIpPort           netip.AddrPort
	ellaId               int64
	tnla                 TNLAssociation
	relativeEllaCapacity int64
	state                int
	name                 string
	regionId             aper.BitString
	setId                aper.BitString
	pointer              aper.BitString
	plmns                *PlmnSupported
	slices               *SliceSupported
	lenSlice             int
	lenPlmn              int
}

type TNLAssociation struct {
	sctpConn         *sctp.SCTPConn
	tnlaWeightFactor int64
	usage            aper.Enumerated
	streams          uint16
}

type SliceSupported struct {
	sst  string
	sd   string
	next *SliceSupported
}

type PlmnSupported struct {
	mcc  string
	mnc  string
	next *PlmnSupported
}

func (ella *GNBElla) GetSliceSupport(index int) (string, string) {
	mov := ella.slices
	for i := 0; i < index; i++ {
		mov = mov.next
	}

	return mov.sst, mov.sd
}

func (ella *GNBElla) GetPlmnSupport(index int) (string, string) {
	mov := ella.plmns
	for i := 0; i < index; i++ {
		mov = mov.next
	}

	return mov.mcc, mov.mnc
}

func convertMccMnc(plmn string) (mcc string, mnc string) {
	if plmn[2] == 'f' {
		mcc = fmt.Sprintf("%c%c%c", plmn[1], plmn[0], plmn[3])
		mnc = fmt.Sprintf("%c%c", plmn[5], plmn[4])
	} else {
		mcc = fmt.Sprintf("%c%c%c", plmn[1], plmn[0], plmn[3])
		mnc = fmt.Sprintf("%c%c%c", plmn[2], plmn[5], plmn[4])
	}

	return mcc, mnc
}

func (ella *GNBElla) AddedPlmn(plmn string) {
	if ella.lenPlmn == 0 {
		newElem := &PlmnSupported{}

		// newElem.info = plmn
		newElem.next = nil
		newElem.mcc, newElem.mnc = convertMccMnc(plmn)
		// update list
		ella.plmns = newElem
		ella.lenPlmn++
		return
	}

	mov := ella.plmns
	for i := 0; i < ella.lenPlmn; i++ {
		// end of the list
		if mov.next == nil {
			newElem := &PlmnSupported{}
			newElem.mcc, newElem.mnc = convertMccMnc(plmn)
			newElem.next = nil

			mov.next = newElem
		} else {
			mov = mov.next
		}
	}

	ella.lenPlmn++
}

func (ella *GNBElla) AddedSlice(sst string, sd string) {
	if ella.lenSlice == 0 {
		newElem := &SliceSupported{}
		newElem.sst = sst
		newElem.sd = sd
		newElem.next = nil

		// update list
		ella.slices = newElem
		ella.lenSlice++
		return
	}

	mov := ella.slices
	for i := 0; i < ella.lenSlice; i++ {
		// end of the list
		if mov.next == nil {
			newElem := &SliceSupported{}
			newElem.sst = sst
			newElem.sd = sd
			newElem.next = nil

			mov.next = newElem
		} else {
			mov = mov.next
		}
	}
	ella.lenSlice++
}

func (ella *GNBElla) GetTNLA() TNLAssociation {
	return ella.tnla
}

func (tnla *TNLAssociation) GetSCTP() *sctp.SCTPConn {
	return tnla.sctpConn
}

func (tnla *TNLAssociation) GetWeightFactor() int64 {
	return tnla.tnlaWeightFactor
}

func (tnla *TNLAssociation) GetUsage() aper.Enumerated {
	return tnla.usage
}

func (tnla *TNLAssociation) Release() error {
	return tnla.sctpConn.Close()
}

func (ella *GNBElla) SetStateInactive() {
	ella.state = Inactive
}

func (ella *GNBElla) SetStateActive() {
	ella.state = Active
}

func (ella *GNBElla) SetStateOverload() {
	ella.state = Overload
}

func (ella *GNBElla) GetState() int {
	return ella.state
}

func (ella *GNBElla) GetSCTPConn() *sctp.SCTPConn {
	return ella.tnla.sctpConn
}

func (ella *GNBElla) SetSCTPConn(conn *sctp.SCTPConn) {
	ella.tnla.sctpConn = conn
}

func (ella *GNBElla) SetTNLAWeight(weight int64) {
	ella.tnla.tnlaWeightFactor = weight
}

func (ella *GNBElla) SetTNLAUsage(usage aper.Enumerated) {
	ella.tnla.usage = usage
}

func (ella *GNBElla) SetTNLAStreams(streams uint16) {
	ella.tnla.streams = streams
}

func (ella *GNBElla) GetTNLAStreams() uint16 {
	return ella.tnla.streams
}

func (ella *GNBElla) GetEllaIpPort() netip.AddrPort {
	return ella.ellaIpPort
}

func (ella *GNBElla) SetEllaIpPort(ap netip.AddrPort) {
	ella.ellaIpPort = ap
}

func (ella *GNBElla) GetEllaId() int64 {
	return ella.ellaId
}

func (ella *GNBElla) setEllaId(id int64) {
	ella.ellaId = id
}

func (ella *GNBElla) GetEllaName() string {
	return ella.name
}

func (ella *GNBElla) GetRegionId() aper.BitString {
	return ella.regionId
}

func (ella *GNBElla) SetRegionId(regionId aper.BitString) {
	ella.regionId = regionId
}

func (ella *GNBElla) GetSetId() aper.BitString {
	return ella.setId
}

func (ella *GNBElla) SetSetId(setId aper.BitString) {
	ella.setId = setId
}

func (ella *GNBElla) GetPointer() aper.BitString {
	return ella.pointer
}

func (ella *GNBElla) SetPointer(pointer aper.BitString) {
	ella.pointer = pointer
}

func (ella *GNBElla) SetEllaName(name string) {
	ella.name = name
}

func (ella *GNBElla) GetEllaCapacity() int64 {
	return ella.relativeEllaCapacity
}

func (ella *GNBElla) SetEllaCapacity(capacity int64) {
	ella.relativeEllaCapacity = capacity
}

func (ella *GNBElla) GetLenPlmns() int {
	return ella.lenPlmn
}

func (ella *GNBElla) GetLenSlice() int {
	return ella.lenSlice
}

func (ella *GNBElla) SetLenPlmns(value int) {
	ella.lenPlmn = value
}

func (ella *GNBElla) SetLenSlice(value int) {
	ella.lenSlice = value
}
