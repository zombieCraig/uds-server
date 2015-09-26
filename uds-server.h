/* (c) 2015 Open Garages */

/* Helper Macros */
#define SET_BIT(val, bitIndex) val |= (1 << bitIndex)
#define CLEAR_BIT(val, bitIndex) val &= ~(1 << bitIndex)
#define TOGGLE_BIT(val, bitIndex) val ^= (1 << bitIndex)
#define IS_SET(val, bitIndex) (val & (1 << bitIndex))

/* OBD-II Modes */
#define OBD_MODE_SHOW_CURRENT_DATA        0x01
#define OBD_MODE_SHOW_FREEZE_FRAME        0x02
#define OBD_MODE_READ_DTC                 0x03
#define OBD_MODE_CLEAR_DTC                0x04
#define OBD_MODE_TEST_RESULTS_NON_CAN     0x05
#define OBD_MODE_TEST_RESULTS_CAN         0x06
#define OBD_MODE_READ_PENDING_DTC         0x07
#define OBD_MODE_CONTROL_OPERATIONS       0x08
#define OBD_MODE_VEHICLE_INFORMATION      0x09
#define OBD_MODE_READ_PERM_DTC            0x0A

/* UDS SIDs */
#define UDS_SID_DIAGNOSTIC_CONTROL        0x10 // GMLAN = Initiate Diagnostics
#define UDS_SID_ECU_RESET                 0x11
#define UDS_SID_GM_READ_FAILURE_RECORD    0x12 // GMLAN
#define UDS_SID_CLEAR_DTC                 0x14
#define UDS_SID_READ_DTC                  0x19
#define UDS_SID_GM_READ_DID_BY_ID         0x1A // GMLAN - Read DID By ID
#define UDS_SID_RESTART_COMMUNICATIONS    0x20 // GMLAN - Restart a stopped com
#define UDS_SID_READ_DATA_BY_ID           0x22
#define UDS_SID_READ_MEM_BY_ADDRESS       0x23
#define UDS_SID_READ_SCALING_BY_ID        0x24
#define UDS_SID_SECURITY_ACCESS           0x27
#define UDS_SID_COMMUNICATION_CONTROL     0x28 // GMLAN Stop Communications
#define UDS_SID_READ_DATA_BY_ID_PERIODIC  0x2A
#define UDS_SID_DEFINE_DATA_ID            0x2C
#define UDS_SID_WRITE_DATA_BY_ID          0x2E
#define UDS_SID_IO_CONTROL_BY_ID          0x2F
#define UDS_SID_ROUTINE_CONTROL           0x31
#define UDS_SID_REQUEST_DOWNLOAD          0x34
#define UDS_SID_REQUEST_UPLOAD            0x35
#define UDS_SID_TRANSFER_DATA             0x36
#define UDS_SID_REQUEST_XFER_EXIT         0x37
#define UDS_SID_REQUEST_XFER_FILE         0x38
#define UDS_SID_WRITE_MEM_BY_ADDRESS      0x3D
#define UDS_SID_TESTER_PRESENT            0x3E
#define UDS_SID_ACCESS_TIMING             0x83
#define UDS_SID_SECURED_DATA_TRANS        0x84
#define UDS_SID_CONTROL_DTC_SETTINGS      0x85
#define UDS_SID_RESPONSE_ON_EVENT         0x86
#define UDS_SID_LINK_CONTROL              0x87
#define UDS_SID_GM_PROGRAMMED_STATE       0xA2
#define UDS_SID_GM_PROGRAMMING_MODE       0xA5
#define UDS_SID_GM_READ_DIAG_INFO         0xA9
#define UDS_SID_GM_READ_DATA_BY_ID        0xAA
#define UDS_SID_GM_DEVICE_CONTROL         0xAE

/* GM READ DIAG SUB FUNCS */
#define UDS_READ_STATUS_BY_MASK           0x81
/* DTC MASK Bitflags */
#define DTC_SUPPORTED_BY_CALIBRATION      1
#define DTC_CURRENT_DTC                   2
#define DTC_TEST_NOT_PASSED_SINCE_CLEARED 4
#define DTC_TEST_FAILED_SINCE_CLEARED     8
#define DTC_HISTORY                       16
#define DTC_TEST_NOT_PASSED_SINCE_POWER   32
#define DTC_CURRENT_DTC_SINCE_POWER       64
#define DTC_WARNING_INDICATOR_STATE       128

/* Periodic Data Message types */
#define PENDING_READ_DATA_BY_ID_GM         1

