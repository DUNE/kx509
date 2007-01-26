#
include Makefile.$(CPU)
#
new.ps: big.picout prot.1
	tbl prot.1 | eqn | $(TROFF) -ms - $(DPOST) >new.ps
big.picout: big.pic
	$(PIC) big.pic >big.picout
new.txt: prot.1
	tbl prot.1 | neqn | nroff -ms - |col -b >new.txt
big.pic: big.fig
	$(FIG2PIC) big.fig big.pic
clean:
	rm -f big.pic big.picout
	rm -f new.ps new.txt
output.txt output.ps: new.ps new.txt
	cp -p new.ps output.ps
	cp -p new.txt output.txt
