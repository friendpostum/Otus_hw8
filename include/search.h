#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <regex>
#include "hash.h"

struct File {
    File(std::string path_, size_t sz, size_t block_sz, std::string hash):
        path(std::move(path_)),
        size(sz),
        block_sz(block_sz),
        block_qty((sz + block_sz - 1) / block_sz),
        content(path, std::ios::binary) {
        hash_alg(hash);
        hash.reserve(block_qty);
    }

    bool operator<(const File &other) const {
        if (duplicate ^ other.duplicate) {
            return other.duplicate < duplicate;
        }
        // return duplicate && hash_blocks[0] < other.hash_blocks[0];
        return duplicate && size < other.size;
    }

    void equal(File &other) {
        if (other.duplicate || size != other.size) return;

        for (size_t i = 0; i < block_qty; ++i) {
            if (hash_calc(i) != other.hash_calc(i)) return;
        }
        duplicate = true;
        other.duplicate = true;
    }

    std::string hash_calc(size_t i) {
        if (hash_blocks.size() <= i) {
            std::string block(block_sz, '\0');
            content.seekg(i * block_sz);
            content.read(&block[0], block_sz);

            hash_blocks.push_back(algorithm->Hash(block.c_str(), block.size()));
        }
        return hash_blocks[i];
    }

    void hash_alg(const std::string &hash_) {
        if (hash_ == "md5")
            algorithm = std::make_unique<MD5Hasher>();
        else if (hash_ == "sha1")
            algorithm = std::make_unique<SHA1Hasher>();
        else
            algorithm = std::make_unique<CRC32Hasher>();
    }

    std::string path;
    std::vector<std::string> hash_blocks;
    size_t size;
    bool duplicate = false;

private:
    std::ifstream content;
    size_t block_sz;
    size_t block_qty;
    std::unique_ptr<IHasher> algorithm;
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
                           hash(std::move(hash)),
                           file_masks(masks),
                           dir_scan(dir_scan),
                           dir_skip(dir_skip){
        scanner();
        find_duplicate();
        print();
    }


private:
    size_t file_min_sz;
    size_t block_sz;
    size_t depth;
    std::string hash;
    const std::vector<std::string> &dir_scan;
    const std::vector<std::string> &dir_skip;
    const std::vector<std::string> &file_masks;
    std::vector<File> file_list;

    void scanner() {
        for(const auto &dir: dir_scan) {
            if(dir_no_skip(dir)) {
                search_files(dir);
            }
        }
    }

    bool dir_no_skip(const std::string & dir){
        return (fs::exists(dir) && std::find(dir_skip.begin(), dir_skip.end(), dir) == std::end(dir_skip));
    }

    void search_files(const std::string &dir) {
        for (auto it = fs::recursive_directory_iterator(dir); it != fs::recursive_directory_iterator(); ++it) {
            if (!depth)
                it.disable_recursion_pending();

            if (it->is_regular_file() && it->file_size() > file_min_sz) {
                if (mask_match(it->path().string(), file_masks))
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
            if(i > 0 && (f.hash_blocks[0] != file_list[i - 1].hash_blocks[0] || f.size != file_list[i - 1].size))
                std::cout << '\n';
            std::cout << f.path << " " << f.size << " " << f.hash_blocks[0] << '\n';
        }
    }

};