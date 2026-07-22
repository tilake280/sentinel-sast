CXX      ?= g++
CC       ?= cc

TS_DIR   := third_party
TS_INC   := -I$(TS_DIR)/tree-sitter/lib/include

CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
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

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

# One compile rule per vendored C file, each with its own grammar src on the
# include path (parser.c includes "tree_sitter/parser.h" from beside itself).
define TS_COMPILE_RULE
build/ts/$(subst /,_,$(basename $(1))).o: $(1) | build/ts
	$$(CC) $$(TSCFLAGS) -I$(dir $(1)) -c $$< -o $$@
endef
$(foreach s,$(TS_SRCS),$(eval $(call TS_COMPILE_RULE,$(s))))

# Analyzer tests need the grammars but not RabbitMQ/curl.
test: $(TS_OBJS) | build
	$(CXX) $(CXXFLAGS) -o build/test_analyzer tests/test_analyzer.cpp \
	    src/analyzer.cpp src/languages.cpp $(TS_OBJS)
	./build/test_analyzer

build build/ts:
	mkdir -p $@

run: $(BIN)
	./$(BIN)

clean:
	rm -rf build
