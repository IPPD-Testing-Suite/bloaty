// Fuzzer harness targeting ELF section and segment header parsing.
// Exercises the StructReader::Memcpy path in elf.cc.

#include "bloaty.h"
#include "bloaty.pb.h"

#include "absl/strings/string_view.h"

using absl::string_view;

namespace bloaty {

class StringPieceInputFile : public InputFile {
 public:
  StringPieceInputFile(string_view data)
      : InputFile("fake_file") {
    data_ = data;
  }
  bool TryOpen(absl::string_view,
               std::unique_ptr<InputFile>& file) override {
    file.reset(new StringPieceInputFile(data_));
    return true;
  }
};

class StringPieceInputFileFactory : public InputFileFactory {
 public:
  StringPieceInputFileFactory(string_view data) : data_(data) {}
 private:
  string_view data_;
  std::unique_ptr<InputFile> OpenFile(
      const std::string&) const override {
    return std::unique_ptr<InputFile>(new StringPieceInputFile(data_));
  }
};

static void RunBloaty(const InputFileFactory& factory,
                      const std::string& data_source) {
  bloaty::RollupOutput output;
  bloaty::Options options;
  std::string error;
  options.add_data_source(data_source);
  options.add_filename("dummy");
  bloaty::BloatyMain(options, factory, &output, &error);
}

}  // namespace bloaty

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* data2 = reinterpret_cast<const char*>(data);
  bloaty::StringPieceInputFileFactory factory(string_view(data2, size));

  bloaty::RunBloaty(factory, "sections");
  bloaty::RunBloaty(factory, "segments");

  return 0;
}
