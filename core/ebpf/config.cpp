// Copyright 2023 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string>
#include <unordered_set>

#include "logger/Logger.h"
#include "ebpf/config.h"
#include "common/ParamExtractor.h"
#include "common/Flags.h"

namespace logtail {
namespace ebpf {

static const int32_t DEFUALT_RECEIVE_EVENT_CHAN_CAP = 4096;
static const bool DEFUALT_ADMIN_DEBUG_MODE = false;
static const std::string DEFUALT_ADMIN_LOG_LEVEL = "warn";
static const bool DEFUALT_ADMIN_PUSH_ALL_SPAN = false;
static const int32_t DEFUALT_AGGREGATION_WINDOW_SECOND = 15;
static const std::string DEFUALT_CONVERAGE_STRATEGY = "combine";
static const std::string DEFUALT_SAMPLE_STRATEGY = "fixedRate";
static const double DEFUALT_SAMPLE_RATE = 0.01;
static const int32_t DEFUALT_SOCKET_SLOW_REQUEST_THRESHOLD_MS = 500;
static const int32_t DEFUALT_SOCKET_MAX_CONN_TRACKDERS = 10000;
static const int32_t DEFUALT_SOCKET_MAX_BAND_WITH_MB_PER_SEC = 30;
static const int32_t DEFUALT_SOCKET_MAX_RAW_RECORD_PER_SEC = 100000;
static const int32_t DEFUALT_PROFILE_SAMPLE_RATE = 10;
static const int32_t DEFUALT_PROFILE_UPLOAD_DURATION = 10;
static const bool DEFUALT_PROCESS_ENABLE_OOM_DETECT = false;

DEFINE_FLAG_INT32(ebpf_receive_event_chan_cap, "ebpf receive event chan cap", DEFUALT_RECEIVE_EVENT_CHAN_CAP);
DEFINE_FLAG_BOOL(ebpf_admin_config_debug_mode, "ebpf admin config debug mode", DEFUALT_ADMIN_DEBUG_MODE);
DEFINE_FLAG_STRING(ebpf_admin_config_log_level, "ebpf admin config log level", DEFUALT_ADMIN_LOG_LEVEL);
DEFINE_FLAG_BOOL(ebpf_admin_config_push_all_span, "ebpf admin config push all span", DEFUALT_ADMIN_PUSH_ALL_SPAN);
DEFINE_FLAG_INT32(ebpf_aggregation_config_agg_window_second, "ebpf aggregation config agg window second", DEFUALT_AGGREGATION_WINDOW_SECOND);
DEFINE_FLAG_STRING(ebpf_converage_config_strategy, "ebpf converage config strategy", DEFUALT_CONVERAGE_STRATEGY);
DEFINE_FLAG_STRING(ebpf_sample_config_strategy, "ebpf sample config strategy", DEFUALT_SAMPLE_STRATEGY);
DEFINE_FLAG_DOUBLE(ebpf_sample_config_config_rate, "ebpf sample config config rate", DEFUALT_SAMPLE_RATE);
DEFINE_FLAG_INT32(ebpf_socket_probe_config_slow_request_threshold_ms, "ebpf socket probe config slow request threshold ms", DEFUALT_SOCKET_SLOW_REQUEST_THRESHOLD_MS);
DEFINE_FLAG_INT32(ebpf_socket_probe_config_max_conn_trackers, "ebpf socket probe config max conn trackers", DEFUALT_SOCKET_MAX_CONN_TRACKDERS);
DEFINE_FLAG_INT32(ebpf_socket_probe_config_max_band_width_mb_per_sec, "ebpf socket probe config max band width mb per sec", DEFUALT_SOCKET_MAX_BAND_WITH_MB_PER_SEC);
DEFINE_FLAG_INT32(ebpf_socket_probe_config_max_raw_record_per_sec, "ebpf socket probe config max raw record per sec", DEFUALT_SOCKET_MAX_RAW_RECORD_PER_SEC);
DEFINE_FLAG_INT32(ebpf_profile_probe_config_profile_sample_rate, "ebpf profile probe config profile sample rate", DEFUALT_PROFILE_SAMPLE_RATE);
DEFINE_FLAG_INT32(ebpf_profile_probe_config_profile_upload_duration, "ebpf profile probe config profile upload duration", DEFUALT_PROFILE_UPLOAD_DURATION);
DEFINE_FLAG_BOOL(ebpf_process_probe_config_enable_oom_detect, "ebpf process probe config enable oom detect", DEFUALT_PROCESS_ENABLE_OOM_DETECT);

//////
bool IsProcessNamespaceFilterTypeValid(const std::string& type);

bool InitObserverNetworkOptionInner(const Json::Value& probeConfig,
                               nami::ObserverNetworkOption& thisObserverNetworkOption,
                               const PipelineContext* mContext,
                               const std::string& sName) {
    std::string errorMsg;
    // MeterHandlerType (Optional)
    if (!GetOptionalStringParam(probeConfig, "MeterHandlerType", thisObserverNetworkOption.mMeterHandlerType, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // SpanHandlerType (Optional)
    if (!GetOptionalStringParam(probeConfig, "SpanHandlerType", thisObserverNetworkOption.mSpanHandlerType, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }

    // EnableProtocols (Optional)
    if (!GetOptionalListParam(probeConfig, "EnableProtocols", thisObserverNetworkOption.mEnableProtocols, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // EnableProtocols (Optional)
    if (!GetOptionalBoolParam(
            probeConfig, "DisableProtocolParse", thisObserverNetworkOption.mDisableProtocolParse, errorMsg)) {
        PARAM_WARNING_DEFAULT(mContext->GetLogger(),
                              mContext->GetAlarm(),
                              errorMsg,
                              false,
                              sName,
                              mContext->GetConfigName(),
                              mContext->GetProjectName(),
                              mContext->GetLogstoreName(),
                              mContext->GetRegion());
    }
    // DisableConnStats (Optional)
    if (!GetOptionalBoolParam(probeConfig, "DisableConnStats", thisObserverNetworkOption.mDisableConnStats, errorMsg)) {
        PARAM_WARNING_DEFAULT(mContext->GetLogger(),
                              mContext->GetAlarm(),
                              errorMsg,
                              false,
                              sName,
                              mContext->GetConfigName(),
                              mContext->GetProjectName(),
                              mContext->GetLogstoreName(),
                              mContext->GetRegion());
    }
    // EnableConnTrackerDump (Optional)
    if (!GetOptionalBoolParam(
            probeConfig, "EnableConnTrackerDump", thisObserverNetworkOption.mEnableConnTrackerDump, errorMsg)) {
        PARAM_WARNING_DEFAULT(mContext->GetLogger(),
                              mContext->GetAlarm(),
                              errorMsg,
                              false,
                              sName,
                              mContext->GetConfigName(),
                              mContext->GetProjectName(),
                              mContext->GetLogstoreName(),
                              mContext->GetRegion());
    }
    return true;
}

bool ExtractProbeConfig(const Json::Value& config, const PipelineContext* mContext, const std::string& sName, Json::Value& probeConfig) {
    std::string errorMsg;
    if (!IsValidMap(config, "ProbeConfig", errorMsg)) {
        PARAM_ERROR_RETURN(mContext->GetLogger(),
                           mContext->GetAlarm(),
                           errorMsg,
                           sName,
                           mContext->GetConfigName(),
                           mContext->GetProjectName(),
                           mContext->GetLogstoreName(),
                           mContext->GetRegion());
    }
    probeConfig = config["ProbeConfig"];
    return true;
}

bool InitObserverNetworkOption(const Json::Value& config, 
                               nami::ObserverNetworkOption& thisObserverNetworkOption,
                               const PipelineContext* mContext,
                               const std::string& sName) {
    Json::Value probeConfig;
    if (!ExtractProbeConfig(config, mContext, sName, probeConfig)) {
        return false;
    }

    return InitObserverNetworkOptionInner(probeConfig, thisObserverNetworkOption, mContext, sName);
}

//////
bool InitSecurityFileFilter(const Json::Value& config,
                            nami::SecurityFileFilter& thisFileFilter,
                            const PipelineContext* mContext,
                            const std::string& sName) {
    std::string errorMsg;
    for (auto& fileFilterItem : config["FilePathFilter"]) {
        nami::SecurityFileFilterItem thisFileFilterItem;
        // FilePath (Mandatory)
        if (!GetMandatoryStringParam(fileFilterItem, "FilePath", thisFileFilterItem.mFilePath, errorMsg)) {
            PARAM_ERROR_RETURN(mContext->GetLogger(),
                               mContext->GetAlarm(),
                               errorMsg,
                               sName,
                               mContext->GetConfigName(),
                               mContext->GetProjectName(),
                               mContext->GetLogstoreName(),
                               mContext->GetRegion());
        }
        // FileName (Optional)
        if (!GetOptionalStringParam(fileFilterItem, "FileName", thisFileFilterItem.mFileName, errorMsg)) {
            PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                 mContext->GetAlarm(),
                                 errorMsg,
                                 sName,
                                 mContext->GetConfigName(),
                                 mContext->GetProjectName(),
                                 mContext->GetLogstoreName(),
                                 mContext->GetRegion());
        }
        thisFileFilter.mFileFilterItem.emplace_back(thisFileFilterItem);
    }
    return true;
}

bool InitSecurityProcessFilter(const Json::Value& config,
                               nami::SecurityProcessFilter& thisProcessFilter,
                               const PipelineContext* mContext,
                               const std::string& sName) {
    std::string errorMsg;
    // NamespaceFilter (Optional)
    if (config.isMember("NamespaceFilter")) {
        if (!config["NamespaceFilter"].isArray()) {
            PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                 mContext->GetAlarm(),
                                 "NamespaceFilter is not of type list",
                                 sName,
                                 mContext->GetConfigName(),
                                 mContext->GetProjectName(),
                                 mContext->GetLogstoreName(),
                                 mContext->GetRegion());
        } else {
            for (auto& namespaceFilterConfig : config["NamespaceFilter"]) {
                nami::SecurityProcessNamespaceFilter thisProcessNamespaceFilter;
                // NamespaceType (Mandatory)
                if (!GetMandatoryStringParam(
                        namespaceFilterConfig, "NamespaceType", thisProcessNamespaceFilter.mNamespaceType, errorMsg)
                    || !IsProcessNamespaceFilterTypeValid(thisProcessNamespaceFilter.mNamespaceType)) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       errorMsg,
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                // ValueList (Mandatory)
                if (!GetMandatoryListParam<std::string>(
                        namespaceFilterConfig, "ValueList", thisProcessNamespaceFilter.mValueList, errorMsg)) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       errorMsg,
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                thisProcessFilter.mNamespaceFilter.emplace_back(thisProcessNamespaceFilter);
            }
        }
    }

    // NamespaceBlackFilter (Optional)
    if (config.isMember("NamespaceBlackFilter")) {
        // 如果用户两个filter都配置了，不去显式阻塞流水线，但是会打印警告并只执行白名单
        if (config.isMember("NamespaceFilter")) {
            PARAM_WARNING_IGNORE(
                mContext->GetLogger(),
                mContext->GetAlarm(),
                "Both NamespaceFilter and NamespaceBlackFilter are configured, only NamespaceFilter will be executed",
                sName,
                mContext->GetConfigName(),
                mContext->GetProjectName(),
                mContext->GetLogstoreName(),
                mContext->GetRegion());
        } else if (!config["NamespaceBlackFilter"].isArray()) {
            PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                 mContext->GetAlarm(),
                                 "NamespaceBlackFilter is not of type list",
                                 sName,
                                 mContext->GetConfigName(),
                                 mContext->GetProjectName(),
                                 mContext->GetLogstoreName(),
                                 mContext->GetRegion());
        } else {
            for (auto& namespaceBlackFilterConfig : config["NamespaceBlackFilter"]) {
                nami::SecurityProcessNamespaceFilter thisProcessNamespaceFilter;
                // NamespaceType (Mandatory)
                if (!GetMandatoryStringParam(namespaceBlackFilterConfig,
                                             "NamespaceType",
                                             thisProcessNamespaceFilter.mNamespaceType,
                                             errorMsg)
                    || !IsProcessNamespaceFilterTypeValid(thisProcessNamespaceFilter.mNamespaceType)) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       errorMsg,
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                // ValueList (Mandatory)
                if (!GetMandatoryListParam<std::string>(
                        namespaceBlackFilterConfig, "ValueList", thisProcessNamespaceFilter.mValueList, errorMsg)) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       errorMsg,
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                thisProcessFilter.mNamespaceBlackFilter.emplace_back(thisProcessNamespaceFilter);
            }
        }
    }
    return true;
}

bool InitSecurityNetworkFilter(const Json::Value& config,
                               nami::SecurityNetworkFilter& thisNetworkFilter,
                               const PipelineContext* mContext,
                               const std::string& sName) {
    std::string errorMsg;
    // DestAddrList (Optional)
    if (!GetOptionalListParam<std::string>(config, "DestAddrList", thisNetworkFilter.mDestAddrList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // DestPortList (Optional)
    if (!GetOptionalListParam<uint32_t>(config, "DestPortList", thisNetworkFilter.mDestPortList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // DestAddrBlackList (Optional)
    if (!GetOptionalListParam<std::string>(config, "DestAddrBlackList", thisNetworkFilter.mDestAddrBlackList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // DestPortBlackList (Optional)
    if (!GetOptionalListParam<uint32_t>(config, "DestPortBlackList", thisNetworkFilter.mDestPortBlackList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // SourceAddrList (Optional)
    if (!GetOptionalListParam<std::string>(config, "SourceAddrList", thisNetworkFilter.mSourceAddrList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // SourcePortList (Optional)
    if (!GetOptionalListParam<uint32_t>(config, "SourcePortList", thisNetworkFilter.mSourcePortList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // SourceAddrBlackList (Optional)
    if (!GetOptionalListParam<std::string>(
            config, "SourceAddrBlackList", thisNetworkFilter.mSourceAddrBlackList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    // SourcePortBlackList (Optional)
    if (!GetOptionalListParam<uint32_t>(
            config, "SourcePortBlackList", thisNetworkFilter.mSourcePortBlackList, errorMsg)) {
        PARAM_WARNING_IGNORE(mContext->GetLogger(),
                             mContext->GetAlarm(),
                             errorMsg,
                             sName,
                             mContext->GetConfigName(),
                             mContext->GetProjectName(),
                             mContext->GetLogstoreName(),
                             mContext->GetRegion());
    }
    return true;
}

bool IsProcessNamespaceFilterTypeValid(const std::string& type) {
    const std::unordered_set<std::string> dic
        = {"Uts", "Ipc", "Mnt", "Pid", "PidForChildren", "Net", "Cgroup", "User", "Time", "TimeForChildren"};
    return dic.find(type) != dic.end();
}


bool SecurityOptions::Init(SecurityFilterType filterType,
                           const Json::Value& config,
                           const PipelineContext* mContext,
                           const std::string& sName) {
    std::string errorMsg;
    // ProbeConfig (Mandatory)
    if (!IsValidList(config, "ProbeConfig", errorMsg)) {
        PARAM_ERROR_RETURN(mContext->GetLogger(),
                           mContext->GetAlarm(),
                           errorMsg,
                           sName,
                           mContext->GetConfigName(),
                           mContext->GetProjectName(),
                           mContext->GetLogstoreName(),
                           mContext->GetRegion());
    }
    for (auto& innerConfig : config["ProbeConfig"]) {
        nami::SecurityOption thisSecurityOption;

        std::string errorMsg;
        // CallName (Optional)
        if (!GetOptionalListParam<std::string>(innerConfig, "CallName", thisSecurityOption.call_names_, errorMsg)) {
            PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                mContext->GetAlarm(),
                                errorMsg,
                                sName,
                                mContext->GetConfigName(),
                                mContext->GetProjectName(),
                                mContext->GetLogstoreName(),
                                mContext->GetRegion());
        }

        // Filter
        switch (filterType) {
            case SecurityFilterType::FILE: {
                nami::SecurityFileFilter thisFileFilter;
                if (!IsValidList(innerConfig, "FilePathFilter", errorMsg)) {
                    PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                        mContext->GetAlarm(),
                                        errorMsg,
                                        sName,
                                        mContext->GetConfigName(),
                                        mContext->GetProjectName(),
                                        mContext->GetLogstoreName(),
                                        mContext->GetRegion());
                } else {
                    if (!InitSecurityFileFilter(innerConfig, thisFileFilter, mContext, sName)) {
                        return false;
                    }
                }
                thisSecurityOption.filter_.emplace<nami::SecurityFileFilter>(thisFileFilter);
                break;
            }
            case SecurityFilterType::PROCESS: {
                nami::SecurityProcessFilter thisProcessFilter;
                if (!InitSecurityProcessFilter(innerConfig, thisProcessFilter, mContext, sName)) {
                    return false;
                }
                thisSecurityOption.filter_.emplace<nami::SecurityProcessFilter>(thisProcessFilter);
                break;
            }
            case SecurityFilterType::NETWORK: {
                nami::SecurityNetworkFilter thisNetworkFilter;
                if (!IsValidMap(innerConfig, "AddrFilter", errorMsg)) {
                    PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                        mContext->GetAlarm(),
                                        errorMsg,
                                        sName,
                                        mContext->GetConfigName(),
                                        mContext->GetProjectName(),
                                        mContext->GetLogstoreName(),
                                        mContext->GetRegion());
                } else {
                    const Json::Value& filterConfig = innerConfig["AddrFilter"];
                    if (!InitSecurityNetworkFilter(filterConfig, thisNetworkFilter, mContext, sName)) {
                        return false;
                    }
                }
                thisSecurityOption.filter_.emplace<nami::SecurityNetworkFilter>(thisNetworkFilter);
                break;
            }
            default:
                PARAM_WARNING_IGNORE(mContext->GetLogger(),
                                    mContext->GetAlarm(),
                                    "Unknown filter type",
                                    sName,
                                    mContext->GetConfigName(),
                                    mContext->GetProjectName(),
                                    mContext->GetLogstoreName(),
                                    mContext->GetRegion());
                return false;
        }


        // if (!thisSecurityOption.Init(filterType, innerConfig, mContext, sName)) {
        //     return false;
        // }
        mOptionList.emplace_back(thisSecurityOption);
    }
    mFilterType = filterType;
    return true;
}

//////
void eBPFAdminConfig::LoadEbpfConfig(const Json::Value& confJson) {
    // receive_event_chan_cap (Optional)
    mReceiveEventChanCap = FLAGS_ebpf_receive_event_chan_cap;
    // admin_config (Optional)
    mAdminConfig = AdminConfig{FLAGS_ebpf_admin_config_debug_mode, FLAGS_ebpf_admin_config_log_level, FLAGS_ebpf_admin_config_push_all_span};
    // aggregation_config (Optional)
    mAggregationConfig = AggregationConfig{FLAGS_ebpf_aggregation_config_agg_window_second};
    // converage_config (Optional)
    mConverageConfig = ConverageConfig{FLAGS_ebpf_converage_config_strategy};
    // sample_config (Optional)
    mSampleConfig = SampleConfig{FLAGS_ebpf_sample_config_strategy, {FLAGS_ebpf_sample_config_config_rate}};
    // socket_probe_config (Optional)
    mSocketProbeConfig = SocketProbeConfig{FLAGS_ebpf_socket_probe_config_slow_request_threshold_ms, FLAGS_ebpf_socket_probe_config_max_conn_trackers, FLAGS_ebpf_socket_probe_config_max_band_width_mb_per_sec, FLAGS_ebpf_socket_probe_config_max_raw_record_per_sec};
    // profile_probe_config (Optional)
    mProfileProbeConfig = ProfileProbeConfig{FLAGS_ebpf_profile_probe_config_profile_sample_rate, FLAGS_ebpf_profile_probe_config_profile_upload_duration};
    // process_probe_config (Optional)
    mProcessProbeConfig = ProcessProbeConfig{FLAGS_ebpf_process_probe_config_enable_oom_detect};
}

//////
void eBPFAdminConfig::LoadEbpfConfigLegal(const Json::Value& confJson) {
    mReceiveEventChanCap = DEFUALT_RECEIVE_EVENT_CHAN_CAP;
    std::string errorMsg;
    if (!confJson.isMember("ebpf")){
        LOG_ERROR(sLogger, ("ebpf", " is not included in the app_config"));
        return;
    }
    const Json::Value& ebpfConfJson = confJson["ebpf"];
    // receive_event_chan_cap (Optional)
    if (!GetOptionalIntParam(ebpfConfJson, "receive_event_chan_cap", mReceiveEventChanCap, errorMsg)) {
        LOG_ERROR(sLogger, ("load receive_event_chan_cap fail", errorMsg));
        return;
    }
    // admin_config (Optional)
    mAdminConfig = AdminConfig{DEFUALT_ADMIN_DEBUG_MODE, DEFUALT_ADMIN_LOG_LEVEL, DEFUALT_ADMIN_PUSH_ALL_SPAN};
    if (ebpfConfJson.isMember("admin_config")) {
        if (!ebpfConfJson["admin_config"].isObject()) {
            LOG_ERROR(sLogger, ("admin_config", " is not a map"));
            return;
        }
        const Json::Value& thisAdminConfig = ebpfConfJson["admin_config"];
        // admin_config.debug_mode (Optional)
        if (!GetOptionalBoolParam(thisAdminConfig, "debug_mode", mAdminConfig.mDebugMode, errorMsg)) {
            LOG_ERROR(sLogger, ("load admin_config.debug_mode fail", errorMsg));
            return;
        }
        // admin_config.log_level (Optional)
        if (!GetOptionalStringParam(thisAdminConfig, "log_level", mAdminConfig.mLogLevel, errorMsg)) {
            LOG_ERROR(sLogger, ("load admin_config.log_level fail", errorMsg));
            return;
        }
        // admin_config.push_all_span (Optional)
        if (!GetOptionalBoolParam(thisAdminConfig, "push_all_span", mAdminConfig.mPushAllSpan, errorMsg)) {
            LOG_ERROR(sLogger, ("load admin_config.push_all_span fail", errorMsg));
            return;
        }
    }
    mAggregationConfig = AggregationConfig{DEFUALT_AGGREGATION_WINDOW_SECOND};
    // aggregation_config (Optional)
    if (ebpfConfJson.isMember("aggregation_config")) {
        if (!ebpfConfJson["aggregation_config"].isObject()) {
            LOG_ERROR(sLogger, ("aggregation_config", " is not a map"));
            return;
        }
        const Json::Value& thisAggregationConfig = ebpfConfJson["aggregation_config"];
        // aggregation_config.agg_window_second (Optional)
        if (!GetOptionalIntParam(
                thisAggregationConfig, "agg_window_second", mAggregationConfig.mAggWindowSecond, errorMsg)) {
            LOG_ERROR(sLogger, ("load aggregation_config.agg_window_second fail", errorMsg));
            return;
        }
    }
    mConverageConfig = ConverageConfig{DEFUALT_CONVERAGE_STRATEGY};
    // converage_config (Optional)
    if (ebpfConfJson.isMember("converage_config")) {
        if (!ebpfConfJson["converage_config"].isObject()) {
            LOG_ERROR(sLogger, ("converage_config", " is not a map"));
            return;
        }
        const Json::Value& thisConverageConfig = ebpfConfJson["converage_config"];
        // converage_config.strategy (Optional)
        if (!GetOptionalStringParam(thisConverageConfig, "strategy", mConverageConfig.mStrategy, errorMsg)) {
            LOG_ERROR(sLogger, ("load converage_config.strategy fail", errorMsg));
            return;
        }
    }
    mSampleConfig = SampleConfig{DEFUALT_SAMPLE_STRATEGY, {DEFUALT_SAMPLE_RATE}};
    // sample_config (Optional)
    if (ebpfConfJson.isMember("sample_config")) {
        if (!ebpfConfJson["sample_config"].isObject()) {
            LOG_ERROR(sLogger, ("sample_config", " is not a map"));
            return;
        }
        const Json::Value& thisSampleConfig = ebpfConfJson["sample_config"];
        // sample_config.strategy (Optional)
        if (!GetOptionalStringParam(thisSampleConfig, "strategy", mSampleConfig.mStrategy, errorMsg)) {
            LOG_ERROR(sLogger, ("load sample_config.strategy fail", errorMsg));
            return;
        }
        // sample_config.config (Optional)
        if (thisSampleConfig.isMember("config")) {
            if (!thisSampleConfig["config"].isObject()) {
                LOG_ERROR(sLogger, ("sample_config.config", " is not a map"));
                return;
            }
            const Json::Value& thisSampleConfigConfig = thisSampleConfig["config"];
            // sample_config.config.rate (Optional)
            if (!GetOptionalDoubleParam(thisSampleConfigConfig, "rate", mSampleConfig.mConfig.mRate, errorMsg)) {
                LOG_ERROR(sLogger, ("load sample_config.config.rate fail", errorMsg));
                return;
            }
        }
    }
    mSocketProbeConfig = SocketProbeConfig{DEFUALT_SOCKET_SLOW_REQUEST_THRESHOLD_MS, DEFUALT_SOCKET_MAX_CONN_TRACKDERS, DEFUALT_SOCKET_MAX_BAND_WITH_MB_PER_SEC, DEFUALT_SOCKET_MAX_RAW_RECORD_PER_SEC};
    // for Observer
    // socket_probe_config (Optional)
    if (ebpfConfJson.isMember("socket_probe_config")) {
        if (!ebpfConfJson["socket_probe_config"].isObject()) {
            LOG_ERROR(sLogger, ("socket_probe_config", " is not a map"));
            return;
        }
        const Json::Value& thisSocketProbeConfig = ebpfConfJson["socket_probe_config"];
        // socket_probe_config.slow_request_threshold_ms (Optional)
        if (!GetOptionalIntParam(thisSocketProbeConfig,
                                 "slow_request_threshold_ms",
                                 mSocketProbeConfig.mSlowRequestThresholdMs,
                                 errorMsg)) {
            LOG_ERROR(sLogger, ("load socket_probe_config.slow_request_threshold_ms fail", errorMsg));
            return;
        }
        // socket_probe_config.max_conn_trackers (Optional)
        if (!GetOptionalIntParam(
                thisSocketProbeConfig, "max_conn_trackers", mSocketProbeConfig.mMaxConnTrackers, errorMsg)) {
            LOG_ERROR(sLogger, ("load socket_probe_config.max_conn_trackers fail", errorMsg));
            return;
        }
        // socket_probe_config.max_band_width_mb_per_sec (Optional)
        if (!GetOptionalIntParam(
                thisSocketProbeConfig, "max_band_width_mb_per_sec", mSocketProbeConfig.mMaxBandWidthMbPerSec, errorMsg)) {
            LOG_ERROR(sLogger, ("load socket_probe_config.max_band_width_mb_per_sec fail", errorMsg));
            return;
        }
        // socket_probe_config.max_raw_record_per_sec (Optional)
        if (!GetOptionalIntParam(
                thisSocketProbeConfig, "max_raw_record_per_sec", mSocketProbeConfig.mMaxRawRecordPerSec, errorMsg)) {
            LOG_ERROR(sLogger, ("load socket_probe_config.max_raw_record_per_sec fail", errorMsg));
            return;
        }
    }
    mProfileProbeConfig = ProfileProbeConfig{DEFUALT_PROFILE_SAMPLE_RATE, DEFUALT_PROFILE_UPLOAD_DURATION};
    // profile_probe_config (Optional)
    if (ebpfConfJson.isMember("profile_probe_config")) {
        if (!ebpfConfJson["profile_probe_config"].isObject()) {
            LOG_ERROR(sLogger, ("profile_probe_config", " is not a map"));
            return;
        }
        const Json::Value& thisProfileProbeConfig = ebpfConfJson["profile_probe_config"];
        // profile_probe_config.profile_sample_rate (Optional)
        if (!GetOptionalIntParam(
                thisProfileProbeConfig, "profile_sample_rate", mProfileProbeConfig.mProfileSampleRate, errorMsg)) {
            LOG_ERROR(sLogger, ("load profile_probe_config.profile_sample_rate fail", errorMsg));
            return;
        }
        // profile_probe_config.profile_upload_duration (Optional)
        if (!GetOptionalIntParam(thisProfileProbeConfig,
                                 "profile_upload_duration",
                                 mProfileProbeConfig.mProfileUploadDuration,
                                 errorMsg)) {
            LOG_ERROR(sLogger, ("load profile_probe_config.profile_upload_duration fail", errorMsg));
            return;
        }
    }
    mProcessProbeConfig = ProcessProbeConfig{DEFUALT_PROCESS_ENABLE_OOM_DETECT};
    // process_probe_config (Optional)
    if (ebpfConfJson.isMember("process_probe_config")) {
        if (!ebpfConfJson["process_probe_config"].isObject()) {
            LOG_ERROR(sLogger, ("process_probe_config", " is not a map"));
            return;
        }
        const Json::Value& thisProcessProbeConfig = ebpfConfJson["process_probe_config"];
        // process_probe_config.enable_oom_detect (Optional)
        if (!GetOptionalBoolParam(
                thisProcessProbeConfig, "enable_oom_detect", mProcessProbeConfig.mEnableOOMDetect, errorMsg)) {
            LOG_ERROR(sLogger, ("load process_probe_config.enable_oom_detect fail", errorMsg));
            return;
        }
    }
}

} // ebpf
} // logtail
