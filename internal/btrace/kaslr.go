package btrace

import "fmt"

type Kaslr struct {
	kaddr uint64
	saddr uint64
}

func NewKaslr(kaddr, saddr uint64) Kaslr {
	return Kaslr{kaddr: kaddr, saddr: saddr}
}

func (k *Kaslr) effectiveAddr(kaddr uint64) uint64 {
	if k.saddr < k.kaddr {
		return kaddr - (k.kaddr - k.saddr)
	}

	return uint64(kaddr + (k.saddr - k.kaddr))
}

func (k *Kaslr) offset() uint64 {
	if k.saddr < k.kaddr {
		return k.kaddr - k.saddr
	}

	return k.saddr - k.kaddr
}

func (k *Kaslr) String() string {
	return fmt.Sprintf("kaddr=%#x saddr=%#x offset=%#x", k.kaddr, k.saddr, k.offset())
}
