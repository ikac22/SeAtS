
git submodule init
git submodule update

SNP_MEASURE=packages/sev-snp-measure
SNPGUEST=packages/snpguest
SNPHOST=packages/snphost

cp $SNP_MEASURE/sev-snp-measure.py bin/

cd $SNPGUEST
cargo build -r
cd -

cp $SNPGUEST/target/release/snpguest bin/

cd $SNPHOST
cargo build -r
cd -

cp $SNPHOST/target/release/snphost bin/

chmod +x bin/*
