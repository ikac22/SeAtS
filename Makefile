BUILDCXX=g++
CHECKCXX=clang++

CXXFLAGS= -Wall -Werror -Wextra -g -pg -O0 -Iinclude/ -DDEBUG
CXXFLREL= -Wall -Werror -Wextra -O3 -s -Iinclude/ -DNDEBUG
CXXFLAGSLIB=$(CXXFLAGS)
CXXFLAGSTST=$(CXXFLAGS) -DRLOG_COMPONENT="seats"

LDFLAGSLIB=
LDFLAGSTST=$(LDFLAGSLIB) -L./target/lib -lseats -lcrypto -lssl

OUTDIR=target
OUTDIRLIB=$(OUTDIR)/lib
OUTDIRTST=$(OUTDIR)/bin
OUTDIROBJ=$(OUTDIR)/obj
OUTFILELIB=libseats.a
OUTFILETST=seatsecho

SRCDIR=src

SRCDIRLIB=$(SRCDIR)/lib
SRCDIRSLIBR := $(shell find $(SRCDIRLIB) -maxdepth 5 -type d)
SRCFILESLIB := $(foreach dir,$(SRCDIRSLIBR),$(wildcard $(dir)/*.cpp))
OBJFILESLIB := $(addprefix $(OUTDIROBJ)/,$(notdir $(patsubst %.cpp,%.o,$(SRCFILESLIB))))

SRCDIRTST=$(SRCDIR)/test
SRCDIRSTSTR := $(shell find $(SRCDIRTST) -maxdepth 3 -type d)
SRCFILESTST := $(foreach dir,$(SRCDIRSTSTR),$(wildcard $(dir)/*.cpp))
OBJFILESTST := $(addprefix $(OUTDIROBJ)/,$(notdir $(patsubst %.cpp,%.o,$(SRCFILESTST))))


.PHONY: all


all: clean lib


clean:
	@rm -rf $(OUTDIR)


lib:$(OBJFILESLIB)
	@mkdir -p $(OUTDIRLIB)
	@echo " TargetLib :" $(OUTDIRLIB)/$(OUTFILELIB) 
	@ ar rcs $(OUTDIRLIB)/$(OUTFILELIB) $^


test:$(OBJFILESTST)
	@mkdir -p $(OUTDIRTST)
	@echo "TargetTest :" $(OUTDIRTST)/$(OUTFILETST)
	@ $(BUILDCXX) $(OBJFILESTST) -o $(OUTDIRTST)/$(OUTFILETST) $(LDFLAGSTST)


release: CXXFLAGSLIB=$(CXXFLREL)
release:$(OBJFILESLIB)   
	@mkdir -p $(OUTDIRLIB)
	@echo "RTargetLib :" $(OUTDIRLIB)/$(OUTFILELIB) 
	@ ar rcs $(OUTDIRLIB)/$(OUTFILELIB) $^


define set_real_src_file
	$(eval REAL_SRC_FILE=$(strip $(1)))
endef

define set_nothing
endef

define get_real_src_file
	$(if $(strip $(findstring $(strip $(1)),$(strip $(2)))),$(call set_real_src_file,$(2)),$(call set_nothing))
endef

define get_source_file
	@echo ObjectFile : $(1)
	$(eval REAL_SRC_SEARCH=$(notdir $(patsubst %.o,%.cpp,$(1))))
	$(eval REAL_SRC_SEARCH=/$(REAL_SRC_SEARCH))
	@echo Sarching : $(REAL_SRC_SEARCH)
	$(eval REAL_SRC_FILE=)
	$(foreach word,$(2), $(call get_real_src_file, $(REAL_SRC_SEARCH),$(word)))
	@echo Using SrcFile : $(REAL_SRC_FILE)
endef


$(OBJFILESLIB): $(SRCFILESLIB)
	@mkdir -p $(OUTDIROBJ)
	$(call get_source_file,$@,$^,$<)
	@ $(BUILDCXX) $(CXXFLAGSLIB) -c $(REAL_SRC_FILE) -o $@


$(OBJFILESTST): $(SRCFILESTST)
	@mkdir -p $(OUTDIROBJ)
	$(call get_source_file,$@,$^,$<)
	@ $(BUILDCXX) $(CXXFLAGSTST) -c $(REAL_SRC_FILE) -o $@

