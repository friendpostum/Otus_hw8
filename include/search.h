#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <regex>
#include "hash.h"

struct File {
    std::string file_path;
    std::ifstream file_content;
    std::vector<std::string> hash;
    size_t file_sz;
    size_t block_sz;
    size_t block_qty;
    std::unique_ptr<IHasher> hasher;
    bool duplicate = false;

    File(std::string path, size_t sz, size_t block_sz, std::string hash):
            file_path(std::move(path)),
            file_sz(sz),
            block_sz(block_sz),
            block_qty((sz + block_sz - 1) / block_sz),
            file_content(file_path, std::ios::binary) {
        set_hasher(hash);
        hash.reserve(block_qty);
    }

    bool operator<(const File &other) const {
        if (duplicate ^ other.duplicate) {
            return other.duplicate < duplicate;
        }
       // return duplicate && hash[0] < other.hash[0];
        return duplicate && file_sz < other.file_sz;
    }

    void equal(File &other) {
        if (other.duplicate || file_sz != other.file_sz) return;

        for (size_t i = 0; i < block_qty; ++i) {
            if (hash_calc(i) != other.hash_calc(i)) return;
        }
        duplicate = true;
        other.duplicate = true;
    }

    std::string hash_calc(size_t i) {
        if (hash.size() <= i) {
            std::string block(block_sz, '\0');
            file_content.seekg(i * block_sz);
            file_content.read(&block[0], block_sz);

            hash.push_back(hasher->Hash(block.c_str(), block.size()));
        }
        return hash[i];
    }

    void set_hasher(const std::string &hash_) {
        if (hash_ == "md5")
            hasher = std::make_unique<MD5Hasher>();
        else if (hash_ == "sha1")
            hasher = std::make_unique<SHA1Hasher>();
        else
            hasher = std::make_unique<CRC32Hasher>();
    }

};

namespace fs = std::filesystem;

struct Search {
    Search(std::string hash,
           const std::vector<std::string> &dir_scan,
           const std::vector<std::string> &dir_skip,
           const std::vector<std::string> &masks,
           size_t file_min_sz,
           size_t block_sz,
           size_t depth) : file_min_sz(file_min_sz),
                           block_sz(block_sz),
                           depth(depth),
                           hash(std::move(hash)){
        scan_dirs(dir_scan, dir_skip, masks);
        find_duplicate();
        print();
    }


private:
    size_t file_min_sz;
    size_t block_sz;
    size_t depth;
    std::string hash;
    std::vector<File> file_list;
    std::vector<std::string> file_masks;


    void scan_dirs(const std::vector<std::string> &dir_scan, const std::vector<std::string> &dir_skip,
                   const std::vector<std::string> &masks) {
        for (const auto &d: dir_scan) {
            if (fs::exists(d)
                && std::find(dir_skip.begin(), dir_skip.end(), d) == std::end(dir_skip)) {
                select_files(d, masks);
            }
        }
    }

    void select_files(const std::string &dir, const std::vector<std::string> &mask) {
        for (auto it = fs::recursive_directory_iterator(dir); it != fs::recursive_directory_iterator(); ++it) {
            if (!depth)
                it.disable_recursion_pending();

            if (it->is_regular_file() && it->file_size() > file_min_sz) {
                if (mask_match(it->path().string(), mask))
                    file_list.emplace_back(it->path().string(), it->file_size(), block_sz, hash);
            }
        }

    }

    static bool mask_match(const std::string &name, const std::vector<std::string> &masks) {
        if (masks.empty()) return true;
        return std::any_of(masks.cbegin(), masks.cend(),
                           [&name](auto m) { return std::regex_match(name, std::regex(m)); });

/*        bool answ = false;
        for(const auto &m: masks)
            if(std::string::npos != name.find(m))
                answ = true;
        return answ;*/
    }

    void find_duplicate() {
        for (auto first = file_list.begin(); first != file_list.end(); ++first) {
            for (auto second = std::next(first); second < file_list.end(); ++second) {
                first->equal(*second);
            }
        }

    }

    void print() {
        std::sort(file_list.begin(), file_list.end());
        for(int i = 0; i < file_list.size(); ++i) {
            const auto &f = file_list[i];
            if(!f.duplicate) break;
            if(i > 0 && (f.hash[0] != file_list[i - 1].hash[0] || f.file_sz != file_list[i - 1].file_sz))
                std::cout << '\n';
            std::cout << f.file_path << " " << f.file_sz << " " << f.hash[0] << '\n';
        }
    }

};