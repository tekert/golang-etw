// Code generated by "stringer -type=TdhOutType,TdhInType -output=gen_tdh_strings.go"; DO NOT EDIT.

package etw

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[TDH_OUTTYPE_NULL-0]
	_ = x[TDH_OUTTYPE_STRING-1]
	_ = x[TDH_OUTTYPE_DATETIME-2]
	_ = x[TDH_OUTTYPE_BYTE-3]
	_ = x[TDH_OUTTYPE_UNSIGNEDBYTE-4]
	_ = x[TDH_OUTTYPE_SHORT-5]
	_ = x[TDH_OUTTYPE_UNSIGNEDSHORT-6]
	_ = x[TDH_OUTTYPE_INT-7]
	_ = x[TDH_OUTTYPE_UNSIGNEDINT-8]
	_ = x[TDH_OUTTYPE_LONG-9]
	_ = x[TDH_OUTTYPE_UNSIGNEDLONG-10]
	_ = x[TDH_OUTTYPE_FLOAT-11]
	_ = x[TDH_OUTTYPE_DOUBLE-12]
	_ = x[TDH_OUTTYPE_BOOLEAN-13]
	_ = x[TDH_OUTTYPE_GUID-14]
	_ = x[TDH_OUTTYPE_HEXBINARY-15]
	_ = x[TDH_OUTTYPE_HEXINT8-16]
	_ = x[TDH_OUTTYPE_HEXINT16-17]
	_ = x[TDH_OUTTYPE_HEXINT32-18]
	_ = x[TDH_OUTTYPE_HEXINT64-19]
	_ = x[TDH_OUTTYPE_PID-20]
	_ = x[TDH_OUTTYPE_TID-21]
	_ = x[TDH_OUTTYPE_PORT-22]
	_ = x[TDH_OUTTYPE_IPV4-23]
	_ = x[TDH_OUTTYPE_IPV6-24]
	_ = x[TDH_OUTTYPE_SOCKETADDRESS-25]
	_ = x[TDH_OUTTYPE_CIMDATETIME-26]
	_ = x[TDH_OUTTYPE_ETWTIME-27]
	_ = x[TDH_OUTTYPE_XML-28]
	_ = x[TDH_OUTTYPE_ERRORCODE-29]
	_ = x[TDH_OUTTYPE_WIN32ERROR-30]
	_ = x[TDH_OUTTYPE_NTSTATUS-31]
	_ = x[TDH_OUTTYPE_HRESULT-32]
	_ = x[TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME-33]
	_ = x[TDH_OUTTYPE_JSON-34]
	_ = x[TDH_OUTTYPE_UTF8-35]
	_ = x[TDH_OUTTYPE_PKCS7_WITH_TYPE_INFO-36]
	_ = x[TDH_OUTTYPE_CODE_POINTER-37]
	_ = x[TDH_OUTTYPE_DATETIME_UTC-38]
	_ = x[TDH_OUTTYPE_REDUCEDSTRING-300]
	_ = x[TDH_OUTTYPE_NOPRINT-301]
}

const (
	_TdhOutType_name_0 = "TDH_OUTTYPE_NULLTDH_OUTTYPE_STRINGTDH_OUTTYPE_DATETIMETDH_OUTTYPE_BYTETDH_OUTTYPE_UNSIGNEDBYTETDH_OUTTYPE_SHORTTDH_OUTTYPE_UNSIGNEDSHORTTDH_OUTTYPE_INTTDH_OUTTYPE_UNSIGNEDINTTDH_OUTTYPE_LONGTDH_OUTTYPE_UNSIGNEDLONGTDH_OUTTYPE_FLOATTDH_OUTTYPE_DOUBLETDH_OUTTYPE_BOOLEANTDH_OUTTYPE_GUIDTDH_OUTTYPE_HEXBINARYTDH_OUTTYPE_HEXINT8TDH_OUTTYPE_HEXINT16TDH_OUTTYPE_HEXINT32TDH_OUTTYPE_HEXINT64TDH_OUTTYPE_PIDTDH_OUTTYPE_TIDTDH_OUTTYPE_PORTTDH_OUTTYPE_IPV4TDH_OUTTYPE_IPV6TDH_OUTTYPE_SOCKETADDRESSTDH_OUTTYPE_CIMDATETIMETDH_OUTTYPE_ETWTIMETDH_OUTTYPE_XMLTDH_OUTTYPE_ERRORCODETDH_OUTTYPE_WIN32ERRORTDH_OUTTYPE_NTSTATUSTDH_OUTTYPE_HRESULTTDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIMETDH_OUTTYPE_JSONTDH_OUTTYPE_UTF8TDH_OUTTYPE_PKCS7_WITH_TYPE_INFOTDH_OUTTYPE_CODE_POINTERTDH_OUTTYPE_DATETIME_UTC"
	_TdhOutType_name_1 = "TDH_OUTTYPE_REDUCEDSTRINGTDH_OUTTYPE_NOPRINT"
)

var (
	_TdhOutType_index_0 = [...]uint16{0, 16, 34, 54, 70, 94, 111, 136, 151, 174, 190, 214, 231, 249, 268, 284, 305, 324, 344, 364, 384, 399, 414, 430, 446, 462, 487, 510, 529, 544, 565, 587, 607, 626, 666, 682, 698, 730, 754, 778}
	_TdhOutType_index_1 = [...]uint8{0, 25, 44}
)

func (i TdhOutType) String() string {
	switch {
	case i <= 38:
		return _TdhOutType_name_0[_TdhOutType_index_0[i]:_TdhOutType_index_0[i+1]]
	case 300 <= i && i <= 301:
		i -= 300
		return _TdhOutType_name_1[_TdhOutType_index_1[i]:_TdhOutType_index_1[i+1]]
	default:
		return "TdhOutType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[TDH_INTYPE_NULL-0]
	_ = x[TDH_INTYPE_UNICODESTRING-1]
	_ = x[TDH_INTYPE_ANSISTRING-2]
	_ = x[TDH_INTYPE_INT8-3]
	_ = x[TDH_INTYPE_UINT8-4]
	_ = x[TDH_INTYPE_INT16-5]
	_ = x[TDH_INTYPE_UINT16-6]
	_ = x[TDH_INTYPE_INT32-7]
	_ = x[TDH_INTYPE_UINT32-8]
	_ = x[TDH_INTYPE_INT64-9]
	_ = x[TDH_INTYPE_UINT64-10]
	_ = x[TDH_INTYPE_FLOAT-11]
	_ = x[TDH_INTYPE_DOUBLE-12]
	_ = x[TDH_INTYPE_BOOLEAN-13]
	_ = x[TDH_INTYPE_BINARY-14]
	_ = x[TDH_INTYPE_GUID-15]
	_ = x[TDH_INTYPE_POINTER-16]
	_ = x[TDH_INTYPE_FILETIME-17]
	_ = x[TDH_INTYPE_SYSTEMTIME-18]
	_ = x[TDH_INTYPE_SID-19]
	_ = x[TDH_INTYPE_HEXINT32-20]
	_ = x[TDH_INTYPE_HEXINT64-21]
	_ = x[TDH_INTYPE_MANIFEST_COUNTEDSTRING-22]
	_ = x[TDH_INTYPE_MANIFEST_COUNTEDANSISTRING-23]
	_ = x[TDH_INTYPE_RESERVED24-24]
	_ = x[TDH_INTYPE_MANIFEST_COUNTEDBINARY-25]
	_ = x[TDH_INTYPE_COUNTEDSTRING-300]
	_ = x[TDH_INTYPE_COUNTEDANSISTRING-301]
	_ = x[TDH_INTYPE_REVERSEDCOUNTEDSTRING-302]
	_ = x[TDH_INTYPE_REVERSEDCOUNTEDANSISTRING-303]
	_ = x[TDH_INTYPE_NONNULLTERMINATEDSTRING-304]
	_ = x[TDH_INTYPE_NONNULLTERMINATEDANSISTRING-305]
	_ = x[TDH_INTYPE_UNICODECHAR-306]
	_ = x[TDH_INTYPE_ANSICHAR-307]
	_ = x[TDH_INTYPE_SIZET-308]
	_ = x[TDH_INTYPE_HEXDUMP-309]
	_ = x[TDH_INTYPE_WBEMSID-310]
}

const (
	_TdhInType_name_0 = "TDH_INTYPE_NULLTDH_INTYPE_UNICODESTRINGTDH_INTYPE_ANSISTRINGTDH_INTYPE_INT8TDH_INTYPE_UINT8TDH_INTYPE_INT16TDH_INTYPE_UINT16TDH_INTYPE_INT32TDH_INTYPE_UINT32TDH_INTYPE_INT64TDH_INTYPE_UINT64TDH_INTYPE_FLOATTDH_INTYPE_DOUBLETDH_INTYPE_BOOLEANTDH_INTYPE_BINARYTDH_INTYPE_GUIDTDH_INTYPE_POINTERTDH_INTYPE_FILETIMETDH_INTYPE_SYSTEMTIMETDH_INTYPE_SIDTDH_INTYPE_HEXINT32TDH_INTYPE_HEXINT64TDH_INTYPE_MANIFEST_COUNTEDSTRINGTDH_INTYPE_MANIFEST_COUNTEDANSISTRINGTDH_INTYPE_RESERVED24TDH_INTYPE_MANIFEST_COUNTEDBINARY"
	_TdhInType_name_1 = "TDH_INTYPE_COUNTEDSTRINGTDH_INTYPE_COUNTEDANSISTRINGTDH_INTYPE_REVERSEDCOUNTEDSTRINGTDH_INTYPE_REVERSEDCOUNTEDANSISTRINGTDH_INTYPE_NONNULLTERMINATEDSTRINGTDH_INTYPE_NONNULLTERMINATEDANSISTRINGTDH_INTYPE_UNICODECHARTDH_INTYPE_ANSICHARTDH_INTYPE_SIZETTDH_INTYPE_HEXDUMPTDH_INTYPE_WBEMSID"
)

var (
	_TdhInType_index_0 = [...]uint16{0, 15, 39, 60, 75, 91, 107, 124, 140, 157, 173, 190, 206, 223, 241, 258, 273, 291, 310, 331, 345, 364, 383, 416, 453, 474, 507}
	_TdhInType_index_1 = [...]uint16{0, 24, 52, 84, 120, 154, 192, 214, 233, 249, 267, 285}
)

func (i TdhInType) String() string {
	switch {
	case i <= 25:
		return _TdhInType_name_0[_TdhInType_index_0[i]:_TdhInType_index_0[i+1]]
	case 300 <= i && i <= 310:
		i -= 300
		return _TdhInType_name_1[_TdhInType_index_1[i]:_TdhInType_index_1[i+1]]
	default:
		return "TdhInType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
