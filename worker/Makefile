CXX      ?= g++
CC       ?= cc

TS_DIR   := third_party
TS_INC   := -I$(TS_DIR)/tree-sitter/lib/include

CXXFLAGS ?= -std=c++23 -Wall -Wextra -Wpedantic -O2
CXXFLAGS += $(TS_INC)
# Vendored C is third-party; don't police its warnings.
TSCFLAGS := -O2 -w $(TS_INC)

LDLIBS   := -lrabbitmq $(shell pkg-config --libs libcurl 2>/dev/null || echo -lcurl)

# Tree-sitter runtime plus one grammar per supported language.
TS_SRCS := $(TS_DIR)/tree-sitter/lib/src/lib.c \
           $(wildcard $(TS_DIR)/tree-sitter-javascript/src/*.c) \
           $(wildcard $(TS_DIR)/tree-sitter-python/src/*.c) \
           $(wildcard $(TS_DIR)/tree-sitter-go/src/*.c)

# Flatten paths so the three parser.c files get distinct object names.
TS_OBJS := $(foreach s,$(TS_SRCS),build/ts/$(subst /,_,$(basename $(s))).o)

SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:src/%.cpp=build/%.o)
BIN := build/sentinel-worker

.PHONY: all clean run test grammars

all: $(BIN)

$(BIN): $(OBJ) $(TS_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

# -MMD -MP writes a .d file beside each object listing the headers it included,
# so editing a header rebuilds every source that depends on it.
build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(OBJ:.o=.d)

# One compile rule per vendored C file, each with its own grammar src on the
# include path (parser.c includes "tree_sitter/parser.h" from beside itself).
define TS_COMPILE_RULE
build/ts/$(subst /,_,$(basename $(1))).o: $(1) | build/ts
	$$(CC) $$(TSCFLAGS) -I$(dir $(1)) -c $$< -o $$@
endef
$(foreach s,$(TS_SRCS),$(eval $(call TS_COMPILE_RULE,$(s))))

# Every source except main.cpp and triage_client.cpp, which pull in RabbitMQ and
# curl. Keeping the analysis core free of I/O dependencies is what lets the test
# suite run with no broker and no database. job.cpp parses queue messages but
# never touches the queue, so it belongs on this side of the line.
ENGINE_SRC := src/analyzer.cpp src/languages.cpp src/ast.cpp src/taint.cpp \
              src/types.cpp src/sanitizers.cpp src/interproc.cpp src/secrets.cpp \
              src/suppress.cpp src/severity.cpp src/vulnerability.cpp src/sarif.cpp \
              src/job.cpp

test: $(TS_OBJS) | build
	$(CXX) $(CXXFLAGS) -o build/test_analyzer tests/test_analyzer.cpp \
	    $(ENGINE_SRC) $(TS_OBJS)
	./build/test_analyzer

build build/ts:
	mkdir -p $@

run: $(BIN)
	./$(BIN)

clean:
	rm -rf build
