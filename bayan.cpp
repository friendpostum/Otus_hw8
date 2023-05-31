#include <boost/program_options.hpp>
#include "search.h"
#include <iostream>

namespace std {
    std::ostream &operator<<(std::ostream &os, const std::vector<std::string> &vec) {
        for(const auto &elem: vec)
            os << elem << " ";

        return os;
    }
}

namespace opt = boost::program_options;

int main(int argc, char *argv[]) {
    try {
        opt::options_description desc{"All options"};
        desc.add_options()
            ("help,h", "produce help message")
            ("hash,H", opt::value<std::string>()->default_value("crc32"), "A hashing algorithm crc32/md5/sha1")
            ("dir_skip,e",
             opt::value<std::vector<std::string>>()->multitoken()->default_value(std::vector<std::string>{}),
             "Skip directories to scanning")
            ("dir_scan,d",
             opt::value<std::vector<std::string>>()->multitoken()->default_value(std::vector<std::string>{"."}),
             "Directories to scanning")
            ("masks,m",
             opt::value<std::vector<std::string>>()->multitoken()->default_value(std::vector<std::string>{".*"}),
             "Mask for files to scans")
            ("depth,l", opt::value<size_t>()->default_value(1), "0-only specified directory/1-all nested directories")
            ("file_sz,s", opt::value<size_t>()->default_value(1), "Minimum size of file")
            ("block_sz,S", opt::value<size_t>()->default_value(1), "Block size in bytes");

        opt::variables_map vm;
        opt::store(opt::parse_command_line(argc, argv, desc), vm);

        if(vm.count("help")) {
            std::cout << desc << "\n";
            return 1;
        }

        try {
            opt::notify(vm);

        } catch(const opt::required_option &e) {
            std::cout << "Error: " << e.what() << std::endl;
            return 2;
        }

/*        try {
            opt::store(opt::parse_config_file<char>("config.cfg", desc), vm);

        } catch(const opt::reading_file &e) {
            std::cout << "Error: " << e.what() << std::endl;
        }*/

        Search search(vm["hash"].as<std::string>(),
                      vm["dir_scan"].as<std::vector<std::string>>(),
                      vm["dir_skip"].as<std::vector<std::string>>(),
                      vm["masks"].as<std::vector<std::string>>(),
                      vm["file_sz"].as<size_t>(),
                      vm["block_sz"].as<size_t>(),
                      vm["depth"].as<size_t>());
    }
    catch(const opt::error &ex) {
        std::cerr << ex.what() << '\n';
    }

    return 0;

}

