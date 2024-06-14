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

#include "ebpf/security/SecurityOptions.h"

#include "common/ParamExtractor.h"

using namespace std;
namespace logtail {

bool SecurityOption::Init(SecurityFilterType filterType,
                          const Json::Value& config,
                          const PipelineContext* mContext,
                          const string& sName) {
    string errorMsg;
    // CallName (Mandatory)
    if (!GetOptionalListParam<string>(config, "CallName", mCallName, errorMsg)) {
        PARAM_ERROR_RETURN(mContext->GetLogger(),
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
            if (!IsValidList(config, "Filter", errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            SecurityFileFilter thisFileFilter;
            for (auto& fileFilterItem : config["Filter"]) {
                SecurityFileFilterItem thisFileFilterItem;
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
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
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
            mFilter.emplace<SecurityFileFilter>(thisFileFilter);
            break;
        }
        case SecurityFilterType::PROCESS: {
            SecurityProcessFilter thisProcessFilter;
            if (!IsValidMap(config, "Filter", errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            const Json::Value& filterConfig = config["Filter"];
            // NamespaceFilter (Optional)
            if (filterConfig.isMember("NamespaceFilter")) {
                if (!filterConfig["NamespaceFilter"].isArray()) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       "NamespaceFilter is not of type list",
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                for (auto& namespaceFilterConfig : filterConfig["NamespaceFilter"]) {
                    SecurityProcessNamespaceFilter thisProcessNamespaceFilter;
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
                    if (!GetMandatoryListParam<string>(
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
                if (filterConfig.isMember("NamespaceBlackFilter")) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       "NamespaceFilter and NamespaceBlackFilter cannot be set at the same time",
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
            }

            // NamespaceBlackFilter (Optional)
            if (filterConfig.isMember("NamespaceBlackFilter")) {
                if (!filterConfig["NamespaceBlackFilter"].isArray()) {
                    PARAM_ERROR_RETURN(mContext->GetLogger(),
                                       mContext->GetAlarm(),
                                       "NamespaceBlackFilter is not of type list",
                                       sName,
                                       mContext->GetConfigName(),
                                       mContext->GetProjectName(),
                                       mContext->GetLogstoreName(),
                                       mContext->GetRegion());
                }
                for (auto& namespaceBlackFilterConfig : filterConfig["NamespaceBlackFilter"]) {
                    SecurityProcessNamespaceFilter thisProcessNamespaceFilter;
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
                    if (!GetMandatoryListParam<string>(
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
            mFilter.emplace<SecurityProcessFilter>(thisProcessFilter);
            break;
        }
        case SecurityFilterType::NETWORK: {
            SecurityNetworkFilter thisNetWorkFilter;
            if (!IsValidMap(config, "Filter", errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            const Json::Value& filterConfig = config["Filter"];
            // DestAddrList (Optional)
            if (!GetOptionalListParam<string>(
                    filterConfig, "DestAddrList", thisNetWorkFilter.mDestAddrList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // DestPortList (Optional)
            if (!GetOptionalListParam<uint32_t>(
                    filterConfig, "DestPortList", thisNetWorkFilter.mDestPortList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // DestAddrBlackList (Optional)
            if (!GetOptionalListParam<string>(
                    filterConfig, "DestAddrBlackList", thisNetWorkFilter.mDestAddrBlackList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // DestPortBlackList (Optional)
            if (!GetOptionalListParam<uint32_t>(
                    filterConfig, "DestPortBlackList", thisNetWorkFilter.mDestPortBlackList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // SourceAddrList (Optional)
            if (!GetOptionalListParam<string>(
                    filterConfig, "SourceAddrList", thisNetWorkFilter.mSourceAddrList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // SourcePortList (Optional)
            if (!GetOptionalListParam<uint32_t>(
                    filterConfig, "SourcePortList", thisNetWorkFilter.mSourcePortList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            // SourceAddrBlackList (Optional)
            if (!GetOptionalListParam<string>(
                    filterConfig, "SourceAddrBlackList", thisNetWorkFilter.mSourceAddrBlackList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
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
                    filterConfig, "SourcePortBlackList", thisNetWorkFilter.mSourcePortBlackList, errorMsg)) {
                PARAM_ERROR_RETURN(mContext->GetLogger(),
                                   mContext->GetAlarm(),
                                   errorMsg,
                                   sName,
                                   mContext->GetConfigName(),
                                   mContext->GetProjectName(),
                                   mContext->GetLogstoreName(),
                                   mContext->GetRegion());
            }
            mFilter.emplace<SecurityNetworkFilter>(thisNetWorkFilter);
            break;
        }
        default:
            PARAM_ERROR_RETURN(mContext->GetLogger(),
                               mContext->GetAlarm(),
                               "Unknown filter type",
                               sName,
                               mContext->GetConfigName(),
                               mContext->GetProjectName(),
                               mContext->GetLogstoreName(),
                               mContext->GetRegion());
    }

    return true;
}

bool SecurityOption::IsProcessNamespaceFilterTypeValid(string type) {
    unordered_set<string> dic
        = {"Uts", "Ipc", "Mnt", "Pid", "PidForChildren", "Net", "Cgroup", "User", "Time", "TimeForChildren"};
    return dic.find(type) != dic.end();
}


bool SecurityOptions::Init(SecurityFilterType filterType,
                           const Json::Value& config,
                           const PipelineContext* mContext,
                           const string& sName) {
    string errorMsg;
    // ConfigList (Mandatory)
    if (!IsValidList(config, "ConfigList", errorMsg)) {
        PARAM_ERROR_RETURN(mContext->GetLogger(),
                           mContext->GetAlarm(),
                           errorMsg,
                           sName,
                           mContext->GetConfigName(),
                           mContext->GetProjectName(),
                           mContext->GetLogstoreName(),
                           mContext->GetRegion());
    }
    for (auto& innerConfig : config["ConfigList"]) {
        SecurityOption thisSecurityOption;
        if (!thisSecurityOption.Init(filterType, innerConfig, mContext, sName)) {
            return false;
        }
        mOptionList.emplace_back(thisSecurityOption);
    }
    mFilterType = filterType;


    switch (mFilterType) {
        case SecurityFilterType::FILE: {
            // 把options的内容打印出来
            for (auto& i : mOptionList) {
                for (auto j : i.mCallName) {
                    LOG_INFO(sLogger, ("callName", j));
                    std::cout << "callName: " << j << " ";
                }
                std::cout << endl;
                SecurityFileFilter fileFilter = std::get<SecurityFileFilter>(i.mFilter);
                for (auto& j : fileFilter.mFileFilterItem) {
                    LOG_INFO(sLogger, ("filePath", j.mFilePath));
                    LOG_INFO(sLogger, ("fileName", j.mFileName));
                    std::cout << "filePath: " << j.mFilePath << std::endl;
                    std::cout << "fileName: " << j.mFileName << std::endl;
                }
                std::cout << endl;
            }
            // TODO: ebpf_start(type);
            break;
        }
        case SecurityFilterType::PROCESS: {
            // 把options的内容打印出来
            for (auto& i : mOptionList) {
                for (auto j : i.mCallName) {
                    LOG_INFO(sLogger, ("callName", j));
                    std::cout << "callName: " << j << std::endl;
                }
                SecurityProcessFilter processFilter = std::get<SecurityProcessFilter>(i.mFilter);
                for (auto& j : processFilter.mNamespaceFilter) {
                    LOG_INFO(sLogger, ("namespaceType", j.mNamespaceType));
                    std::cout << "namespaceType: " << j.mNamespaceType << std::endl;
                    for (auto& k : j.mValueList) {
                        LOG_INFO(sLogger, ("value", k));
                        std::cout << "value: " << k << std::endl;
                    }
                }
                for (auto& j : processFilter.mNamespaceBlackFilter) {
                    LOG_INFO(sLogger, ("namespaceType", j.mNamespaceType));
                    std::cout << "namespaceType: " << j.mNamespaceType << std::endl;
                    for (auto& k : j.mValueList) {
                        LOG_INFO(sLogger, ("value", k));
                        std::cout << "value: " << k << std::endl;
                    }
                }
            }
            // TODO: ebpf_start(type);
            break;
        }
        case SecurityFilterType::NETWORK: {
            // 把options的内容打印出来
            for (auto& i : mOptionList) {
                for (auto j : i.mCallName) {
                    LOG_INFO(sLogger, ("callName", j));
                    std::cout << "callName: " << j << std::endl;
                }
                SecurityNetworkFilter networkFilter = std::get<SecurityNetworkFilter>(i.mFilter);
                for (auto& j : networkFilter.mDestAddrList) {
                    LOG_INFO(sLogger, ("destAddr", j));
                    std::cout << "destAddr: " << j << std::endl;
                }
                for (auto& j : networkFilter.mDestPortList) {
                    LOG_INFO(sLogger, ("destPort", j));
                    std::cout << "destPort: " << j << std::endl;
                }
                for (auto& j : networkFilter.mDestAddrBlackList) {
                    LOG_INFO(sLogger, ("destAddrBlack", j));
                    std::cout << "destAddrBlack: " << j << std::endl;
                }
                for (auto& j : networkFilter.mDestPortBlackList) {
                    LOG_INFO(sLogger, ("destPortBlack", j));
                    std::cout << "destPortBlack: " << j << std::endl;
                }
                for (auto& j : networkFilter.mSourceAddrList) {
                    LOG_INFO(sLogger, ("sourceAddr", j));
                    std::cout << "sourceAddr: " << j << std::endl;
                }
                for (auto& j : networkFilter.mSourcePortList) {
                    LOG_INFO(sLogger, ("sourcePort", j));
                    std::cout << "sourcePort: " << j << std::endl;
                }
                for (auto& j : networkFilter.mSourceAddrBlackList) {
                    LOG_INFO(sLogger, ("sourceAddrBlack", j));
                    std::cout << "sourceAddrBlack: " << j << std::endl;
                }
                for (auto& j : networkFilter.mSourcePortBlackList) {
                    LOG_INFO(sLogger, ("sourcePortBlack", j));
                    std::cout << "sourcePortBlack: " << j << std::endl;
                }
            }
            // TODO: ebpf_start(type);
            break;
        }
        default:
            break;
    }
    return true;
}

// todo app_config中定义的进程级别配置获取


} // namespace logtail
