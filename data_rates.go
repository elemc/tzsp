package tzsp

import "fmt"

// DataRate is a type for represent data rates
type DataRate byte

// Data rates (MB/s)
const (
	DataRate1   DataRate = 0x02
	DataRate2   DataRate = 0x04
	DataRate5_5 DataRate = 0x0b
	DataRate6   DataRate = 0x0c
	DataRate9   DataRate = 0x12
	DataRate11  DataRate = 0x16
	DataRate12  DataRate = 0x18
	DataRate18  DataRate = 0x24
	DataRate22  DataRate = 0x2c
	DataRate24  DataRate = 0x30
	DataRate33  DataRate = 0x42
	DataRate36  DataRate = 0x48
	DataRate48  DataRate = 0x60
	DataRate54  DataRate = 0x6c

	DataRateOld1   DataRate = 0x0a
	DataRateOld2   DataRate = 0x14
	DataRateOld5_5 DataRate = 0x37
	DataRateOld11  DataRate = 0x6e
)

var dataRateMapping = map[DataRate]string{
	DataRate1:      "1MB/s",
	DataRate2:      "2MB/s",
	DataRate5_5:    "5.5MB/s",
	DataRate6:      "6MB/s",
	DataRate9:      "9MB/s",
	DataRate11:     "11MB/s",
	DataRate12:     "12MB/s",
	DataRate18:     "18MB/s",
	DataRate22:     "22MB/s",
	DataRate24:     "24MB/s",
	DataRate33:     "33MB/s",
	DataRate36:     "36MB/s",
	DataRate48:     "48MB/s",
	DataRate54:     "54MB/s",
	DataRateOld1:   "1MB/s",
	DataRateOld2:   "2MB/s",
	DataRateOld5_5: "5.5MB/s",
	DataRateOld11:  "11MB/s",
}

func (dr DataRate) String() string {
	if v, ok := dataRateMapping[dr]; ok {
		return v
	}
	return fmt.Sprintf("unknown data rate: %d", dr)
}
