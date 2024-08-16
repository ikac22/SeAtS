SNP_MEASURE_SCRIPT=sev-snp-measure.py
OVMF_CODE_PATH=/home/ma200282/AMDSEV/sev_build/share/qemu/OVMF_CODE.fd
OVMF_VARS_PATH=/home/ma200282/AMDSEV/sev_build/share/qemu/OVMF_VARS.fd

$SNP_MEASURE_SCRIPT --mode snp --vcpus 4 --vcpu-type=EPYC-v4 --ovmf=$OVMF_CODE_PATH --vars-file=$OVMF_VARS_PATH
