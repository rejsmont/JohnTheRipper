/*
* This software is Copyright (c) 2011,2013 Lukas Odzioba <ukasz at openwall dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_H
#define _CUDA_COMMON_H

#include <cuda_runtime.h>

/*
* CUDA device id specified by -device parameter
*/
int cuda_gpu_id;

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))
extern char *get_cuda_header_version();
extern void cuda_init(unsigned int cuda_gpu_id);
extern void cuda_done(void);
#ifdef HAVE_NVML
extern void cuda_get_temp(unsigned int cuda_gpu_id, unsigned int *temp,
                          unsigned int *fanspeed, unsigned int *util);
#endif

#define check_mem_allocation(inbuffer,outbuffer)\
    if(inbuffer==NULL){\
      fprintf(stderr,"Cannot allocate memory for passwords file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }\
    if(outbuffer==NULL){\
      fprintf(stderr,"Cannot allocate memory for hashes file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }

extern void cuda_init(unsigned int cuda_gpu_id);
extern void advance_cursor();
extern void cuda_device_list();

extern void HandleError(cudaError_t err, const char *file, int line);

#endif
