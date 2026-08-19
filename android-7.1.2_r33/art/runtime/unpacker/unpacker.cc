#include "unpacker.h"
#include "unpacker_code_item.h"
#include "base/macros.h"
#include "globals.h"
#include "instrumentation.h"
#include "art_method-inl.h"
#include "thread.h"
#include "reflection.h"
#include "object_lock.h"

#include <android/log.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits>
#include <string>
#include <unistd.h>
#include <vector>

#define ULOG_TAG "unpacker"
#define TOSTR(fmt) #fmt
#define UFMT TOSTR([%s:%d])

#define ULOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, ULOG_TAG, UFMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ULOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, ULOG_TAG, UFMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ULOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO, ULOG_TAG, UFMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ULOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, ULOG_TAG, UFMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ULOGV(fmt, ...) __android_log_print(ANDROID_LOG_VERBOSE, ULOG_TAG, UFMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)


#define UNPACKER_WORKSPACE "unpacker"
#define UNPACKER_V1_CONFIG "/data/local/tmp/unpacker.tasks.v1.json"
#define UNPACKER_V1_MAX_CONFIG_SIZE (1024 * 1024)
#define UNPACKER_V1_MAX_TASKS 1000
#define UNPACKER_V1_MAX_CODE_ITEM_SIZE (4 * 1024 * 1024)

namespace art {

static bool Unpacker_fake_invoke_ = false;
static bool Unpacker_real_invoke_ = false;
static Thread* Unpacker_self_ = nullptr;
static std::string Unpacker_dump_dir_;
static std::string Unpacker_dex_dir_;
static std::string Unpacker_method_dir_;
static std::string Unpacker_json_path_;
static int Unpacker_json_fd_ = -1;
static cJSON* Unpacker_json_ = nullptr;
static std::list<const DexFile*> Unpacker_dex_files_;
static mirror::ClassLoader* Unpacker_class_loader_ = nullptr;
static std::map<std::string, int> Unpacker_method_fds_;
static std::map<const DexFile*, std::string> Unpacker_dex_sha256_;
static ArtMethod* Unpacker_target_method_ = nullptr;
static std::vector<uint8_t> Unpacker_before_code_item_;
static std::vector<uint8_t> Unpacker_dumped_code_item_;
static bool Unpacker_dump_succeeded_ = false;

struct UnpackerV1Task {
  std::string dex_sha256;
  uint32_t method_idx;
  std::string class_descriptor;
  std::string name;
  std::string signature;
  uint32_t access_flags;
  std::string invoke_policy;
};

struct UnpackerV1Config {
  std::string run_id;
  std::string package_name;
  std::vector<UnpackerV1Task> tasks;
};

static bool UnpackerWriteAll(int fd, const void* data, size_t size) {
  const uint8_t* cursor = reinterpret_cast<const uint8_t*>(data);
  while (size > 0) {
    ssize_t written = TEMP_FAILURE_RETRY(write(fd, cursor, size));
    if (written <= 0) {
      return false;
    }
    cursor += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

static std::string UnpackerReadFile(const std::string& path, size_t max_size, bool* too_large) {
  if (too_large != nullptr) {
    *too_large = false;
  }
  int fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    return std::string();
  }
  std::string data;
  std::array<char, 4096> buffer;
  size_t read_limit = max_size == std::numeric_limits<size_t>::max() ? max_size : max_size + 1;
  while (data.size() < read_limit) {
    size_t remaining = read_limit - data.size();
    size_t request = std::min(buffer.size(), remaining);
    ssize_t count = TEMP_FAILURE_RETRY(read(fd, buffer.data(), request));
    if (count < 0) {
      data.clear();
      break;
    }
    if (count == 0) {
      break;
    }
    data.append(buffer.data(), static_cast<size_t>(count));
  }
  close(fd);
  if (data.size() > max_size) {
    if (too_large != nullptr) {
      *too_large = true;
    }
    return std::string();
  }
  return data;
}

static bool UnpackerAtomicWrite(const std::string& path, const std::string& data) {
  std::string temporary = path + ".tmp";
  int fd = TEMP_FAILURE_RETRY(open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
  if (fd == -1) {
    return false;
  }
  bool success = UnpackerWriteAll(fd, data.data(), data.size()) && fsync(fd) == 0;
  if (close(fd) != 0) {
    success = false;
  }
  if (!success || rename(temporary.c_str(), path.c_str()) != 0) {
    unlink(temporary.c_str());
    return false;
  }
  return true;
}

static bool UnpackerValidRunId(const std::string& value) {
  if (value.empty() || value.size() > 64) {
    return false;
  }
  char first = value.front();
  if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
        (first >= '0' && first <= '9'))) {
    return false;
  }
  for (char ch : value) {
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')) {
      return false;
    }
  }
  return true;
}

static bool UnpackerValidSha256(const std::string& value) {
  if (value.size() != 64) {
    return false;
  }
  for (char ch : value) {
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
      return false;
    }
  }
  return true;
}

static bool UnpackerJsonString(cJSON* object, const char* name, std::string* output) {
  cJSON* item = cJSON_GetObjectItemCaseSensitive(object, name);
  if (!cJSON_IsString(item)) {
    return false;
  }
  char* value = cJSON_GetStringValue(item);
  if (value == nullptr) {
    return false;
  }
  *output = value;
  return true;
}

static bool UnpackerJsonUint32(cJSON* object, const char* name, uint32_t* output) {
  cJSON* item = cJSON_GetObjectItemCaseSensitive(object, name);
  if (!cJSON_IsNumber(item)) {
    return false;
  }
  double value = cJSON_GetNumberValue(item);
  if (!std::isfinite(value) || value < 0 ||
      value > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  double integer_part = 0;
  if (std::modf(value, &integer_part) > 0) {
    return false;
  }
  *output = static_cast<uint32_t>(integer_part);
  return true;
}

static bool UnpackerLoadV1Config(UnpackerV1Config* config, std::string* reason) {
  bool too_large = false;
  std::string data = UnpackerReadFile(
      UNPACKER_V1_CONFIG, UNPACKER_V1_MAX_CONFIG_SIZE, &too_large);
  if (too_large) {
    *reason = "task_config_too_large";
    return false;
  }
  if (data.empty()) {
    *reason = "task_config_missing_or_empty";
    return false;
  }
  cJSON* root = cJSON_ParseWithOpts(data.c_str(), nullptr, true);
  if (root == nullptr) {
    *reason = "task_config_invalid_json";
    return false;
  }
  uint32_t version = 0;
  cJSON* tasks = cJSON_GetObjectItemCaseSensitive(root, "tasks");
  bool valid = UnpackerJsonUint32(root, "version", &version) && version == 1 &&
               UnpackerJsonString(root, "run_id", &config->run_id) &&
               UnpackerJsonString(root, "package", &config->package_name) &&
               UnpackerValidRunId(config->run_id) && cJSON_IsArray(tasks);
  if (!valid) {
    cJSON_Delete(root);
    *reason = "task_config_invalid_header";
    return false;
  }
  int task_count = cJSON_GetArraySize(tasks);
  if (task_count <= 0 || task_count > UNPACKER_V1_MAX_TASKS) {
    cJSON_Delete(root);
    *reason = "task_config_invalid_task_count";
    return false;
  }
  config->tasks.clear();
  for (int index = 0; index < task_count; ++index) {
    cJSON* item = cJSON_GetArrayItem(tasks, index);
    UnpackerV1Task task;
    valid = item != nullptr &&
            UnpackerJsonString(item, "dex_sha256", &task.dex_sha256) &&
            UnpackerJsonUint32(item, "method_idx", &task.method_idx) &&
            UnpackerJsonString(item, "class_descriptor", &task.class_descriptor) &&
            UnpackerJsonString(item, "name", &task.name) &&
            UnpackerJsonString(item, "signature", &task.signature) &&
            UnpackerJsonUint32(item, "access_flags", &task.access_flags) &&
            UnpackerJsonString(item, "invoke_policy", &task.invoke_policy) &&
            UnpackerValidSha256(task.dex_sha256) &&
            task.class_descriptor.size() >= 3 && task.class_descriptor.front() == 'L' &&
            task.class_descriptor.back() == ';' &&
            task.name != "<init>" && task.name != "<clinit>" &&
            task.signature.compare(0, 2, "()") == 0 &&
            (task.access_flags & (kAccNative | kAccAbstract)) == 0 &&
            (task.invoke_policy == "static_no_args" ||
             task.invoke_policy == "instance_zero_no_args");
    bool task_static = (task.access_flags & kAccStatic) != 0;
    valid = valid && ((task.invoke_policy == "static_no_args" && task_static) ||
                      (task.invoke_policy == "instance_zero_no_args" && !task_static));
    for (const UnpackerV1Task& existing : config->tasks) {
      if (existing.dex_sha256 == task.dex_sha256 && existing.method_idx == task.method_idx) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      cJSON_Delete(root);
      config->tasks.clear();
      *reason = StringPrintf("task_config_invalid_task_%d", index);
      return false;
    }
    config->tasks.push_back(task);
  }
  cJSON_Delete(root);
  return true;
}

static bool UnpackerClearJniException(JNIEnv* env) {
  if (!env->ExceptionCheck()) {
    return false;
  }
  env->ExceptionClear();
  return true;
}

static std::string UnpackerCurrentProcessName(JNIEnv* env) {
  jclass activity_thread = env->FindClass("android/app/ActivityThread");
  if (activity_thread == nullptr || UnpackerClearJniException(env)) {
    return std::string();
  }
  jmethodID current_process_name = env->GetStaticMethodID(
      activity_thread, "currentProcessName", "()Ljava/lang/String;");
  if (current_process_name == nullptr || UnpackerClearJniException(env)) {
    env->DeleteLocalRef(activity_thread);
    return std::string();
  }
  jstring value = reinterpret_cast<jstring>(
      env->CallStaticObjectMethod(activity_thread, current_process_name));
  if (value == nullptr || UnpackerClearJniException(env)) {
    env->DeleteLocalRef(activity_thread);
    return std::string();
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  std::string result = chars == nullptr ? std::string() : std::string(chars);
  if (chars != nullptr) {
    env->ReleaseStringUTFChars(value, chars);
  }
  env->DeleteLocalRef(value);
  env->DeleteLocalRef(activity_thread);
  return result;
}

static std::string UnpackerDexSha256(JNIEnv* env, const DexFile* dex_file) {
  auto cached = Unpacker_dex_sha256_.find(dex_file);
  if (cached != Unpacker_dex_sha256_.end()) {
    return cached->second;
  }
  jclass digest_class = env->FindClass("java/security/MessageDigest");
  if (digest_class == nullptr || UnpackerClearJniException(env)) {
    return std::string();
  }
  jmethodID get_instance = env->GetStaticMethodID(
      digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
  jmethodID update = env->GetMethodID(digest_class, "update", "([BII)V");
  jmethodID digest_method = env->GetMethodID(digest_class, "digest", "()[B");
  if (get_instance == nullptr || update == nullptr || digest_method == nullptr ||
      UnpackerClearJniException(env)) {
    env->DeleteLocalRef(digest_class);
    return std::string();
  }
  jstring algorithm = env->NewStringUTF("SHA-256");
  jobject digest = env->CallStaticObjectMethod(digest_class, get_instance, algorithm);
  if (digest == nullptr || UnpackerClearJniException(env)) {
    env->DeleteLocalRef(algorithm);
    env->DeleteLocalRef(digest_class);
    return std::string();
  }
  const size_t chunk_size = 64 * 1024;
  jbyteArray chunk = env->NewByteArray(chunk_size);
  if (chunk == nullptr || UnpackerClearJniException(env)) {
    env->DeleteLocalRef(digest);
    env->DeleteLocalRef(algorithm);
    env->DeleteLocalRef(digest_class);
    return std::string();
  }
  const uint8_t* begin = dex_file->Begin();
  size_t size = dex_file->Size();
  for (size_t offset = 0; offset < size; offset += chunk_size) {
    size_t count = std::min(chunk_size, size - offset);
    env->SetByteArrayRegion(chunk, 0, count, reinterpret_cast<const jbyte*>(begin + offset));
    env->CallVoidMethod(digest, update, chunk, 0, static_cast<jint>(count));
    if (UnpackerClearJniException(env)) {
      env->DeleteLocalRef(chunk);
      env->DeleteLocalRef(digest);
      env->DeleteLocalRef(algorithm);
      env->DeleteLocalRef(digest_class);
      return std::string();
    }
  }
  jbyteArray result = reinterpret_cast<jbyteArray>(env->CallObjectMethod(digest, digest_method));
  std::string hex;
  if (result != nullptr && !UnpackerClearJniException(env) && env->GetArrayLength(result) == 32) {
    std::array<jbyte, 32> bytes;
    env->GetByteArrayRegion(result, 0, bytes.size(), bytes.data());
    static const char digits[] = "0123456789abcdef";
    hex.resize(64);
    for (size_t index = 0; index < bytes.size(); ++index) {
      uint8_t value = static_cast<uint8_t>(bytes[index]);
      hex[index * 2] = digits[value >> 4];
      hex[index * 2 + 1] = digits[value & 0x0f];
    }
  }
  if (result != nullptr) {
    env->DeleteLocalRef(result);
  }
  env->DeleteLocalRef(chunk);
  env->DeleteLocalRef(digest);
  env->DeleteLocalRef(algorithm);
  env->DeleteLocalRef(digest_class);
  if (!hex.empty()) {
    Unpacker_dex_sha256_[dex_file] = hex;
  }
  return hex;
}

static std::string UnpackerTaskStatePath(const UnpackerV1Config& config, size_t task_index) {
  return StringPrintf("%s/v1/%s/state/%06zu.json", Unpacker_dump_dir_.c_str(),
                      config.run_id.c_str(), task_index);
}

static bool UnpackerEnsureTaskStateDir(const UnpackerV1Config& config) {
  std::string v1_dir = Unpacker_dump_dir_ + "/v1";
  std::string run_dir = v1_dir + "/" + config.run_id;
  std::string state_dir = run_dir + "/state";
  return (mkdir(v1_dir.c_str(), 0700) == 0 || errno == EEXIST) &&
         (mkdir(run_dir.c_str(), 0700) == 0 || errno == EEXIST) &&
         (mkdir(state_dir.c_str(), 0700) == 0 || errno == EEXIST);
}

static std::string UnpackerReadTaskStatus(const std::string& path) {
  bool too_large = false;
  std::string data = UnpackerReadFile(path, 64 * 1024, &too_large);
  if (too_large) {
    return "invalid";
  }
  if (data.empty()) {
    return "pending";
  }
  cJSON* root = cJSON_ParseWithOpts(data.c_str(), nullptr, true);
  if (root == nullptr) {
    return "invalid";
  }
  std::string status;
  bool valid = UnpackerJsonString(root, "status", &status);
  cJSON_Delete(root);
  return valid ? status : "invalid";
}

static bool UnpackerWriteTaskState(const UnpackerV1Config& config, size_t task_index,
                                   const UnpackerV1Task& task, const char* status,
                                   const std::string& reason) {
  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "version", 1);
  cJSON_AddStringToObject(root, "run_id", config.run_id.c_str());
  cJSON_AddNumberToObject(root, "task_index", task_index);
  cJSON_AddStringToObject(root, "dex_sha256", task.dex_sha256.c_str());
  cJSON_AddNumberToObject(root, "method_idx", task.method_idx);
  cJSON_AddStringToObject(root, "class_descriptor", task.class_descriptor.c_str());
  cJSON_AddStringToObject(root, "name", task.name.c_str());
  cJSON_AddStringToObject(root, "signature", task.signature.c_str());
  cJSON_AddStringToObject(root, "status", status);
  cJSON_AddStringToObject(root, "reason", reason.c_str());
  char* json = cJSON_PrintUnformatted(root);
  bool success = json != nullptr &&
      UnpackerAtomicWrite(UnpackerTaskStatePath(config, task_index),
                          std::string(json) + "\n");
  if (json != nullptr) {
    free(json);
  }
  cJSON_Delete(root);
  return success;
}

std::string Unpacker::getDumpDir() {
  Thread* const self = Thread::Current();
  JNIEnv* env = self->GetJniEnv();
  jclass cls_ActivityThread = env->FindClass("android/app/ActivityThread");
  jmethodID mid_currentActivityThread = env->GetStaticMethodID(cls_ActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
  jobject obj_ActivityThread = env->CallStaticObjectMethod(cls_ActivityThread, mid_currentActivityThread);
  jfieldID fid_mInitialApplication = env->GetFieldID(cls_ActivityThread, "mInitialApplication", "Landroid/app/Application;");
  jobject obj_mInitialApplication = env->GetObjectField(obj_ActivityThread, fid_mInitialApplication);
  jclass cls_Context = env->FindClass("android/content/Context");
  jmethodID mid_getApplicationInfo = env->GetMethodID(cls_Context, "getApplicationInfo",
                                                      "()Landroid/content/pm/ApplicationInfo;");
  jobject obj_app_info = env->CallObjectMethod(obj_mInitialApplication, mid_getApplicationInfo);
  jclass cls_ApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
  jfieldID fid_dataDir = env->GetFieldID(cls_ApplicationInfo, "dataDir", "Ljava/lang/String;");
  jstring dataDir = (jstring)env->GetObjectField(obj_app_info, fid_dataDir);
  const char *cstr_dataDir = env->GetStringUTFChars(dataDir, nullptr);
  std::string dump_dir(cstr_dataDir);
  dump_dir += "/";
  dump_dir += UNPACKER_WORKSPACE;
  env->ReleaseStringUTFChars(dataDir, cstr_dataDir);
  return dump_dir;
}

std::string Unpacker::getDexDumpPath(const DexFile* dex_file) {
  std::string dex_location = dex_file->GetLocation();
  size_t size = dex_file->Size();
  //替换windows文件不支持的字符
  for (size_t i = 0; i < dex_location.length(); i++) {
    if (dex_location[i] == '/' || dex_location[i] == ':') {
      dex_location[i] = '_';
    }
  }
  std::string dump_path = Unpacker_dex_dir_ + "/" + dex_location;
  dump_path += StringPrintf("_%zu.dex", size);
  return dump_path;
}

std::string Unpacker::getMethodDumpPath(ArtMethod* method) {
  CHECK(method->GetDeclaringClass() != nullptr) << method;
  const DexFile& dex_file = method->GetDeclaringClass()->GetDexFile();
  std::string dex_location = dex_file.GetLocation();
  size_t size = dex_file.Size();
  //替换windows文件不支持的字符
  for (size_t i = 0; i < dex_location.length(); i++) {
    if (dex_location[i] == '/' || dex_location[i] == ':') {
      dex_location[i] = '_';
    }
  }
  std::string dump_path = Unpacker_method_dir_ + "/" + dex_location;
  dump_path += StringPrintf("_%zu_codeitem.bin", size);
  return dump_path;
}

cJSON* Unpacker::createJson() {
  cJSON *json;
  cJSON *dexes;

  json = cJSON_CreateObject();
  if (json == nullptr) {
      goto bail;
  }
  dexes = cJSON_AddArrayToObject(json, "dexes");
  if (dexes == nullptr) {
      goto bail;
  }
bail:
  return json;
}

cJSON* Unpacker::parseJson() {
  if (Unpacker_json_fd_ == -1) {
    return nullptr;
  }

  lseek(Unpacker_json_fd_, 0, SEEK_SET);
  struct stat json_stat = {};
  if (fstat(Unpacker_json_fd_, &json_stat)) {
    ULOGE("fstat error: %s", strerror(errno));
    return nullptr;
  }
  int size = (int)json_stat.st_size;
  if (size == 0) {
    return nullptr;
  }

  char* buf = new char[size];
  ssize_t read_size = read(Unpacker_json_fd_, buf, size);
  if (read_size != (ssize_t)size) {
    ULOGW("fread %s %zd/%d error: %s", Unpacker_json_path_.c_str(), read_size, size, strerror(errno));
  }
  cJSON *json = cJSON_Parse(buf);
  if (json == nullptr) {
      const char *error_ptr = cJSON_GetErrorPtr();
      if (error_ptr != nullptr) {
        ULOGE("cJSON_Parse error: %s", error_ptr);
      }
  }
  delete[] buf;
  return json;
}

void Unpacker::writeJson() {
  if (Unpacker_json_fd_ == -1) {
    return;
  }
  lseek(Unpacker_json_fd_, 0, SEEK_SET);
  int fail = ftruncate(Unpacker_json_fd_, 0);
  if (fail) {
    ULOGW("ftruncate %s error: %s", Unpacker_json_path_.c_str(), strerror(errno));
  }
  char* json_str = cJSON_Print(Unpacker_json_);
  CHECK(json_str != nullptr);
  ssize_t written_size = write(Unpacker_json_fd_, json_str, strlen(json_str));
  if (written_size != (ssize_t)strlen(json_str)) {
    ULOGW("fwrite %s %zd/%zu error: %s", Unpacker_json_path_.c_str(), written_size, strlen(json_str), strerror(errno));
  }
  free(json_str);
}

std::list<const DexFile*> Unpacker::getDexFiles() {
  std::list<const DexFile*> dex_files;
  Thread* const self = Thread::Current();
  ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
  ReaderMutexLock mu(self, *class_linker->DexLock());
  const std::list<ClassLinker::DexCacheData>& dex_caches = class_linker->GetDexCachesData();
  for (auto it = dex_caches.begin(); it != dex_caches.end(); ++it) {
    ClassLinker::DexCacheData data = *it;
    const DexFile* dex_file = data.dex_file;
    const std::string& dex_location = dex_file->GetLocation();
    if (dex_location.rfind("/system/", 0) == 0) {
      continue;
    }
    dex_files.push_back(dex_file);
  }
  return dex_files;
}

mirror::ClassLoader* Unpacker::getAppClassLoader() {
  Thread* const self = Thread::Current();
  ScopedObjectAccessUnchecked soa(self);
  JNIEnv* env = self->GetJniEnv();
  jclass cls_ActivityThread = env->FindClass("android/app/ActivityThread");
  jmethodID mid_currentActivityThread = env->GetStaticMethodID(cls_ActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
  jobject obj_ActivityThread = env->CallStaticObjectMethod(cls_ActivityThread, mid_currentActivityThread);
  jfieldID fid_mInitialApplication = env->GetFieldID(cls_ActivityThread, "mInitialApplication", "Landroid/app/Application;");
  jobject obj_mInitialApplication = env->GetObjectField(obj_ActivityThread, fid_mInitialApplication);
  jclass cls_Context = env->FindClass("android/content/Context");
  jmethodID mid_getClassLoader = env->GetMethodID(cls_Context, "getClassLoader", "()Ljava/lang/ClassLoader;");
  jobject obj_classLoader = env->CallObjectMethod(obj_mInitialApplication, mid_getClassLoader);
  return soa.Decode<mirror::ClassLoader*>(obj_classLoader);
}

void Unpacker::invokeAllMethods() {
  Thread* const self = Thread::Current();
  ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
  JNIEnv* env = self->GetJniEnv();
  UnpackerV1Config config;
  std::string config_reason;
  if (!UnpackerLoadV1Config(&config, &config_reason)) {
    ULOGW("V1 task config unavailable: %s", config_reason.c_str());
    return;
  }
  std::string process_name = UnpackerCurrentProcessName(env);
  if (process_name != config.package_name) {
    ULOGE("V1 package mismatch: expected %s, actual %s", config.package_name.c_str(),
          process_name.c_str());
    return;
  }
  if (!UnpackerEnsureTaskStateDir(config)) {
    ULOGE("V1 cannot create state directory: %s", strerror(errno));
    return;
  }

  StackHandleScope<1> loader_scope(self);
  Handle<mirror::ClassLoader> h_class_loader(
      loader_scope.NewHandle(Unpacker_class_loader_));
  if (h_class_loader.Get() == nullptr) {
    ULOGE("V1 app class loader is unavailable");
    return;
  }
  for (size_t task_index = 0; task_index < config.tasks.size(); ++task_index) {
    const UnpackerV1Task& task = config.tasks[task_index];
    std::string state_path = UnpackerTaskStatePath(config, task_index);
    std::string state = UnpackerReadTaskStatus(state_path);
    if (state == "running") {
      UnpackerWriteTaskState(config, task_index, task, "crashed",
                             "process_terminated_while_running");
      continue;
    }
    if (state == "recovered" || state == "no_change" || state == "crashed" ||
        state == "skipped") {
      continue;
    }
    if (state != "pending") {
      UnpackerWriteTaskState(config, task_index, task, "skipped", "invalid_state_file");
      continue;
    }

    auto finish = [&](const char* status, const std::string& reason) {
      if (!UnpackerWriteTaskState(config, task_index, task, status, reason)) {
        ULOGE("V1 cannot write %s for task %zu: %s", status, task_index, strerror(errno));
      }
      ULOGI("V1 task %zu %s:%u %s: %s", task_index, task.dex_sha256.c_str(),
            task.method_idx, status, reason.c_str());
    };

    const DexFile* target_dex = nullptr;
    for (const DexFile* dex_file : Unpacker_dex_files_) {
      std::string digest = UnpackerDexSha256(env, dex_file);
      if (digest == task.dex_sha256) {
        target_dex = dex_file;
        break;
      }
    }
    if (target_dex == nullptr) {
      finish("skipped", "dex_sha256_not_loaded");
      return;
    }
    if (task.method_idx >= target_dex->NumMethodIds()) {
      finish("skipped", "method_idx_out_of_range");
      return;
    }
    const DexFile::MethodId& method_id = target_dex->GetMethodId(task.method_idx);
    std::string actual_class = target_dex->GetMethodDeclaringClassDescriptor(method_id);
    std::string actual_name = target_dex->GetMethodName(method_id);
    std::string actual_signature = target_dex->GetMethodSignature(method_id).ToString();
    if (actual_class != task.class_descriptor || actual_name != task.name ||
        actual_signature != task.signature) {
      finish("skipped", "dex_method_metadata_mismatch");
      return;
    }

    uint32_t class_index = 0;
    bool class_found = false;
    for (; class_index < target_dex->NumClassDefs(); ++class_index) {
      const DexFile::ClassDef& class_def = target_dex->GetClassDef(class_index);
      if (task.class_descriptor == target_dex->GetClassDescriptor(class_def)) {
        class_found = true;
        break;
      }
    }
    if (!class_found) {
      finish("skipped", "declaring_class_not_defined_in_dex");
      return;
    }

    mirror::DexCache* dex_cache = class_linker->FindDexCache(self, *target_dex, false);
    if (dex_cache == nullptr) {
      finish("skipped", "dex_cache_not_found");
      return;
    }
    StackHandleScope<1> dex_cache_scope(self);
    Handle<mirror::DexCache> h_dex_cache(dex_cache_scope.NewHandle(dex_cache));
    const DexFile::ClassDef& class_def = target_dex->GetClassDef(class_index);
    mirror::Class* klass = class_linker->ResolveType(
        *target_dex, class_def.class_idx_, h_dex_cache, h_class_loader);
    if (klass == nullptr) {
      if (self->IsExceptionPending()) {
        self->ClearException();
      }
      finish("skipped", "resolve_class_failed");
      return;
    }
    StackHandleScope<1> class_scope(self);
    Handle<mirror::Class> h_class(class_scope.NewHandle(klass));
    if (!h_class->IsInitialized()) {
      finish("skipped", "class_not_already_initialized");
      return;
    }

    ArtMethod* target_method = nullptr;
    size_t pointer_size = class_linker->GetImagePointerSize();
    for (ArtMethod& method : h_class->GetDeclaredMethods(pointer_size)) {
      if (method.GetDexMethodIndex() == task.method_idx) {
        target_method = &method;
        break;
      }
    }
    if (target_method == nullptr) {
      finish("skipped", "declared_method_not_found");
      return;
    }
    if (target_method->IsProxyMethod() || !target_method->IsInvokable() ||
        target_method->IsNative() || target_method->IsAbstract() ||
        target_method->IsConstructor()) {
      finish("skipped", "runtime_method_policy_rejected");
      return;
    }
    bool runtime_static = target_method->IsStatic();
    bool policy_static = task.invoke_policy == "static_no_args";
    if (runtime_static != policy_static ||
        (target_method->GetAccessFlags() & (kAccStatic | kAccNative | kAccAbstract)) !=
        (task.access_flags & (kAccStatic | kAccNative | kAccAbstract))) {
      finish("skipped", "runtime_access_flags_mismatch");
      return;
    }
    if (ArtMethod::NumArgRegisters(target_method->GetShorty()) != 0) {
      finish("skipped", "runtime_method_has_arguments");
      return;
    }

    if (!UnpackerWriteTaskState(config, task_index, task, "running", "invoke_started")) {
      ULOGE("V1 cannot persist running state for task %zu", task_index);
      return;
    }
    Unpacker_before_code_item_.clear();
    const DexFile::CodeItem* before = target_method->GetCodeItem();
    if (before != nullptr) {
      size_t before_size = Unpacker::getCodeItemSize(target_method);
      if (before_size > 0 && before_size <= UNPACKER_V1_MAX_CODE_ITEM_SIZE) {
        const uint8_t* begin = reinterpret_cast<const uint8_t*>(before);
        Unpacker_before_code_item_.assign(begin, begin + before_size);
      }
    }
    Unpacker_target_method_ = target_method;
    Unpacker_dumped_code_item_.clear();
    Unpacker_dump_succeeded_ = false;
    Unpacker::enableFakeInvoke();

    uint32_t args_size = runtime_static ? 0 : 1;
    std::vector<uint32_t> args(args_size, 0);
    if (!runtime_static) {
      mirror::Object* receiver = h_class->AllocObject(self);
      if (receiver == nullptr) {
        Unpacker::disableFakeInvoke();
        Unpacker_target_method_ = nullptr;
        if (self->IsExceptionPending()) {
          self->ClearException();
        }
        finish("skipped", "receiver_allocation_failed");
        return;
      }
      args[0] = StackReference<mirror::Object>::FromMirrorPtr(receiver).AsVRegValue();
    }
    JValue result;
    target_method->Invoke(self, args.data(), args_size, &result, target_method->GetShorty());
    bool invoke_exception = self->IsExceptionPending();
    if (invoke_exception) {
      self->ClearException();
    }
    Unpacker::disableFakeInvoke();
    Unpacker::disableRealInvoke();
    Unpacker_target_method_ = nullptr;

    if (!Unpacker_dump_succeeded_) {
      finish("no_change", invoke_exception ? "invoke_exception_without_dump" :
                                             "target_method_not_dumped");
    } else if (Unpacker_before_code_item_ == Unpacker_dumped_code_item_) {
      finish("no_change", "code_item_identical");
    } else {
      finish("recovered", "code_item_changed_and_dumped");
    }
    return;
  }
}

void Unpacker::dumpAllDexes() {
  for (const DexFile* dex_file : Unpacker_dex_files_) {
    std::string dump_path = getDexDumpPath(dex_file);
    if (access(dump_path.c_str(), F_OK) != -1) {
      ULOGI("%s already dumped, ignored", dump_path.c_str());
      continue;
    }
    const uint8_t* begin = dex_file->Begin();
    size_t size = dex_file->Size();
    int fd = open(dump_path.c_str(), O_RDWR | O_CREAT, 0777);
    if (fd == -1) {
      ULOGE("open %s error: %s", dump_path.c_str(), strerror(errno));
      continue;
    }

    std::vector<uint8_t> data(size);
    memcpy(data.data(), "dex\n035", 8);
    memcpy(data.data() + 8, begin + 8, size - 8);

    size_t written_size = write(fd, data.data(), size);
    if (written_size < size) {
      ULOGW("fwrite %s %zu/%zu error: %s", dump_path.c_str(), written_size, size, strerror(errno));
    }
    close(fd);
    ULOGI("dump dex %s to %s successful!", dex_file->GetLocation().c_str(), dump_path.c_str());
  }
}

void Unpacker::init() {
  Unpacker_fake_invoke_ = false;
  Unpacker_self_ = Thread::Current();
  Unpacker_dump_dir_ = getDumpDir();
  mkdir(Unpacker_dump_dir_.c_str(), 0777);
  Unpacker_dex_dir_ = getDumpDir() + "/dex";
  mkdir(Unpacker_dex_dir_.c_str(), 0777);
  Unpacker_method_dir_ = getDumpDir() + "/method";
  mkdir(Unpacker_method_dir_.c_str(), 0777);
  Unpacker_json_path_ = getDumpDir() + "/unpacker.json";
  Unpacker_json_fd_ = -1;
  Unpacker_json_fd_ = open(Unpacker_json_path_.c_str(), O_RDWR | O_CREAT, 0777);
  if (Unpacker_json_fd_ == -1) {
    ULOGE("open %s error: %s", Unpacker_json_path_.c_str(), strerror(errno));
  }
  Unpacker_json_ = parseJson();
  if (Unpacker_json_ == nullptr) {
    Unpacker_json_ = createJson();
  }
  CHECK(Unpacker_json_ != nullptr);

  Unpacker_dex_files_ = getDexFiles();
  Unpacker_class_loader_ = getAppClassLoader();
}

void Unpacker::fini() {
  Unpacker_fake_invoke_ = false;
  Unpacker_real_invoke_ = false;
  Unpacker_self_ = nullptr;
  Unpacker_target_method_ = nullptr;
  Unpacker_before_code_item_.clear();
  Unpacker_dumped_code_item_.clear();
  Unpacker_dump_succeeded_ = false;
  if (Unpacker_json_fd_ != -1) {
    close(Unpacker_json_fd_);
    Unpacker_json_fd_ = -1;
  }
  for(auto iter = Unpacker_method_fds_.begin(); iter != Unpacker_method_fds_.end(); iter++) {
    close(iter->second);
  }
  Unpacker_method_fds_.clear();
  Unpacker_dex_files_.clear();
  Unpacker_class_loader_ = nullptr;
  if (Unpacker_json_ != nullptr) {
    cJSON_Delete(Unpacker_json_);
    Unpacker_json_ = nullptr;
  }
}

void Unpacker::unpack() {
  ScopedObjectAccess soa(Thread::Current());
  ULOGI("%s", "unpack begin!");
  init();
  invokeAllMethods();
  fini();
  ULOGI("%s", "unpack end!");
}

void Unpacker::enableFakeInvoke() {
  Unpacker_fake_invoke_ = true;
}

void Unpacker::disableFakeInvoke() {
  Unpacker_fake_invoke_ = false;
}

bool Unpacker::isFakeInvoke(Thread *self, ArtMethod *method) {
  if (Unpacker_fake_invoke_ && self == Unpacker_self_ && method == Unpacker_target_method_) {
      return true;
  }
  return false;
}

void Unpacker::enableRealInvoke() {
  Unpacker_real_invoke_ = true;
}

void Unpacker::disableRealInvoke() {
  Unpacker_real_invoke_ = false;
}

bool Unpacker::isRealInvoke(Thread *self, ArtMethod *method) {
  if (Unpacker_real_invoke_ && self == Unpacker_self_ && method == Unpacker_target_method_) {
      return true;
  }
  return false;
}

size_t Unpacker::getCodeItemSize(ArtMethod* method) {
  if (method == nullptr) {
    return 0;
  }
  const DexFile* dex_file = method->GetDexFile();
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  if (dex_file == nullptr || code_item == nullptr || dex_file->Begin() == nullptr) {
    return 0;
  }
  uintptr_t dex_begin = reinterpret_cast<uintptr_t>(dex_file->Begin());
  uintptr_t code_begin = reinterpret_cast<uintptr_t>(code_item);
  if (dex_file->Size() > std::numeric_limits<uintptr_t>::max() - dex_begin) {
    return 0;
  }
  uintptr_t dex_end = dex_begin + dex_file->Size();
  if (code_begin < dex_begin || code_begin >= dex_end) {
    return 0;
  }
  size_t size = 0;
  size_t available = static_cast<size_t>(dex_end - code_begin);
  if (!youpk_v1::MeasureCodeItemSize(reinterpret_cast<const uint8_t*>(code_item), available,
                                     UNPACKER_V1_MAX_CODE_ITEM_SIZE, &size)) {
    return 0;
  }
  return size;
}

void Unpacker::dumpMethod(ArtMethod *method, int nop_size) {
  if (method != Unpacker_target_method_) {
    return;
  }
  std::string dump_path = Unpacker::getMethodDumpPath(method);
  int fd = -1;
  if (Unpacker_method_fds_.find(dump_path) != Unpacker_method_fds_.end()) {
    fd = Unpacker_method_fds_[dump_path];
  }
  else {
    fd = open(dump_path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0777);
    if (fd == -1) {
      ULOGE("open %s error: %s", dump_path.c_str(), strerror(errno));
      return;
    }
    Unpacker_method_fds_[dump_path] = fd;
  }

  uint32_t index = method->GetDexMethodIndex();
  std::string str_name = PrettyMethod(method);
  const char* name = str_name.c_str();
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  uint32_t code_item_size = (uint32_t)Unpacker::getCodeItemSize(method);
  if (code_item == nullptr || code_item_size == 0 ||
      code_item_size > UNPACKER_V1_MAX_CODE_ITEM_SIZE ||
      nop_size < 0 || static_cast<uint32_t>(nop_size) > code_item_size -
          offsetof(DexFile::CodeItem, insns_)) {
    ULOGW("invalid CodeItem for %s", PrettyMethod(method).c_str());
    return;
  }

  size_t total_size = 4 + strlen(name) + 1 + 4 + code_item_size;
  std::vector<uint8_t> data(total_size);
  uint8_t* buf = data.data();
  memcpy(buf, &index, 4);
  buf += 4;
  memcpy(buf, name, strlen(name) + 1);
  buf += strlen(name) + 1;
  memcpy(buf, &code_item_size, 4);
  buf += 4;
  memcpy(buf, code_item, code_item_size);
  if (nop_size != 0) {
    memset(buf + offsetof(DexFile::CodeItem, insns_), 0, nop_size);
  }
  Unpacker_dumped_code_item_.assign(buf, buf + code_item_size);
  if (!UnpackerWriteAll(fd, data.data(), total_size) || fsync(fd) != 0) {
    ULOGW("write %s in %s error: %s", PrettyMethod(method).c_str(), dump_path.c_str(),
          strerror(errno));
    Unpacker_dumped_code_item_.clear();
    return;
  }
  Unpacker_dump_succeeded_ = true;
}

//继续解释执行返回false, dump完成返回true
bool Unpacker::beforeInstructionExecute(Thread *self, ArtMethod *method, uint32_t dex_pc, int inst_count) {
  if (Unpacker::isFakeInvoke(self, method)) {
    const DexFile::CodeItem* code_item = method->GetCodeItem();
    if (code_item == nullptr || Unpacker::getCodeItemSize(method) == 0 ||
        dex_pc >= code_item->insns_size_in_code_units_) {
      return true;
    }
    const uint16_t* const insns = code_item->insns_;
    const Instruction* inst = Instruction::At(insns + dex_pc);
    uint16_t inst_data = inst->Fetch16(0);
    Instruction::Code opcode = inst->Opcode(inst_data);

    //对于一般的方法抽取(非ijiami, najia), 直接在第一条指令处dump即可
    if (inst_count == 0 && opcode != Instruction::GOTO && opcode != Instruction::GOTO_16 && opcode != Instruction::GOTO_32) {
      Unpacker::dumpMethod(method);
      return true;
    }
    //ijiami, najia的特征为: goto: goto_decrypt; nop; ... ; return; const vx, n; invoke-static xxx; goto: goto_origin;
    else if (inst_count == 0 && opcode >= Instruction::GOTO && opcode <= Instruction::GOTO_32) {
      return false;
    } else if (inst_count == 1 && opcode >= Instruction::CONST_4 && opcode <= Instruction::CONST_WIDE_HIGH16) {
      return false;
    } else if (inst_count == 2 && (opcode == Instruction::INVOKE_STATIC || opcode == Instruction::INVOKE_STATIC_RANGE)) {
      //让这条指令真正的执行
      Unpacker::disableFakeInvoke();
      Unpacker::enableRealInvoke();
      return false;
    } else if (inst_count == 3) {
      if (opcode >= Instruction::GOTO && opcode <= Instruction::GOTO_32) {
        //写入时将第一条GOTO用nop填充
        const Instruction* inst_first = Instruction::At(insns);
        Instruction::Code first_opcode = inst_first->Opcode(inst_first->Fetch16(0));
        CHECK(first_opcode >= Instruction::GOTO && first_opcode <= Instruction::GOTO_32);
        ULOGD("found najia/ijiami %s", PrettyMethod(method).c_str());
        switch (first_opcode)
        {
        case Instruction::GOTO:
          Unpacker::dumpMethod(method, 2);
          break;
        case Instruction::GOTO_16:
          Unpacker::dumpMethod(method, 4);
          break;
        case Instruction::GOTO_32:
          Unpacker::dumpMethod(method, 8);
          break;
        default:
          break;
        }
      } else {
        Unpacker::dumpMethod(method);
      }
      return true;
    }
    Unpacker::dumpMethod(method);
    return true;
  }
  return false;
}

bool Unpacker::afterInstructionExecute(Thread *self, ArtMethod *method, uint32_t dex_pc, int inst_count) {
  if (!Unpacker::isRealInvoke(self, method)) {
    return false;
  }
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  if (code_item == nullptr || Unpacker::getCodeItemSize(method) == 0 ||
      dex_pc >= code_item->insns_size_in_code_units_) {
    Unpacker::enableFakeInvoke();
    Unpacker::disableRealInvoke();
    return false;
  }
  const uint16_t* const insns = code_item->insns_;
  const Instruction* inst = Instruction::At(insns + dex_pc);
  uint16_t inst_data = inst->Fetch16(0);
  Instruction::Code opcode = inst->Opcode(inst_data);
  if (inst_count == 2 &&
      (opcode == Instruction::INVOKE_STATIC || opcode == Instruction::INVOKE_STATIC_RANGE)) {
    Unpacker::enableFakeInvoke();
    Unpacker::disableRealInvoke();
  }
  return false;
}

//注册native方法

static void Unpacker_unpackNative(JNIEnv*, jclass) {
  Unpacker::unpack();
}

static JNINativeMethod gMethods[] = {
  NATIVE_METHOD(Unpacker, unpackNative, "()V")
};

void Unpacker::register_cn_youlor_Unpacker(JNIEnv* env) {
  REGISTER_NATIVE_METHODS("cn/youlor/Unpacker");
}

}
