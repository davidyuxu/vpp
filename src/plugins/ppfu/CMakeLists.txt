# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

find_path(DPDK_INCLUDE_DIR PATH_SUFFIXES dpdk NAMES rte_config.h HINTS
	  ${DPDK_INCLUDE_DIR_HINT})
find_library(DPDK_LIB NAMES libdpdk.a HINTS ${DPDK_LIB_DIR_HINT})

include_directories (${DPDK_INCLUDE_DIR})

#message(STATUS ${DPDK_INCLUDE_DIR_HINT})
#message(STATUS ${DPDK_INCLUDE_DIR})

message(STATUS ${DPDK_LIB})

#include_directories (${DPDK_INCLUDE_DIR}/zuc/include)
#include_directories (${DPDK_INCLUDE_DIR}/snow3g/include)


get_filename_component(DPDK_LIB_DIR ${DPDK_LIB} DIRECTORY)
set(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR} -Wl,--whole-archive,-l:libsso_snow3g.a,-l:libsso_zuc.a,--no-whole-archive")

add_vpp_plugin(ppfu
  SOURCES
  ppf_gtpu_encap.c
  ppf_gtpu_decap.c
  ppf_gtpu.c
  ppf_pdcp_decrypt.c
  ppf_pdcp_encrypt.c
  ppf_pdcp_input.c
  ppf_sb_path_lb.c
  ppf_srb_nb_rx.c
  ppf_srb_nb_tx.c
  ppf_srb.c
  ppf_pdcp.c
  ppfu.c
  ppfu_api.c
  snow3g.c
  ppfu_handoff.c

  API_FILES
  ppfu.api
  ppf_gtpu.api
  
  INSTALL_HEADERS
  ppf_gtpu_all_api_h.h
  ppf_gtpu_msg_enum.h
  ppfu_all_api_h.h
  ppfu_msg_enum.h
  
  API_TEST_SOURCES
  ppfu_test.c 
  
  LINK_FLAGS
  ${DPDK_LINK_FLAGS}
)

