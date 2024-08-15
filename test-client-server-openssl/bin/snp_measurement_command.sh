SNP_MEASURE_SCRIPT=sev-snp-measure.py
OVMF_CODE_PATH=/home/ma200282/AMDSEV/sev_build/share/qemu/OVMF_CODE.fd
OVMF_VARS_PATH=/home/ma200282/AMDSEV/sev_build/share/qemu/OVMF_VARS.fd

$SNP_MEASURE_SCRIPT --mode snp --vspus 4 --vspu-type=EPYC-v4 --ovmf=$OVMF_CODE_PATH --vars-file=$OVMF_VARS_PATH
