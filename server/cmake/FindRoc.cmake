# SPDX-License-Identifier: MIT
#
# FindRoc.cmake - locate the system Roc Toolkit (libroc) only.
#
# We intentionally never vendor or redistribute libroc (PROTOCOL OQ-7).

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_ROC QUIET roc)
endif()

find_path(Roc_INCLUDE_DIR
  NAMES roc/roc.h roc/context.h
  HINTS ${PC_ROC_INCLUDE_DIRS})
find_library(Roc_LIBRARY
  NAMES roc
  HINTS ${PC_ROC_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Roc
  REQUIRED_VARS Roc_LIBRARY Roc_INCLUDE_DIR)

if(Roc_FOUND AND NOT TARGET Roc::Roc)
  add_library(Roc::Roc UNKNOWN IMPORTED)
  set_target_properties(Roc::Roc PROPERTIES
    IMPORTED_LOCATION "${Roc_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Roc_INCLUDE_DIR}")
endif()

mark_as_advanced(Roc_INCLUDE_DIR Roc_LIBRARY)
