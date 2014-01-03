#include <ctype.h>
#ifdef HAVE_NVML
#include <nvml.h>
#endif

#include "cuda_common.h"
#include "options.h"
#include "john.h"

#ifndef HAVE_OPENCL
/* If we have OpenCL as well, we use its exact same function */
void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };

	if (john_main_process) {
		fprintf(stderr, "%c\b", cursor[pos]);
		pos = (pos + 1) % 4;
	}
}
#endif

void cuda_init(unsigned int cuda_gpu_id)
{
	int devices;
	struct list_entry *current;

#ifdef HAVE_NVML
	nvmlInit();
#endif
	if ((current = options.gpu_devices->head)) {
		if (current->next) {
			fprintf(stderr, "Only one CUDA device supported.\n");
			exit(1);
		}
		if (!isdigit(current->data[0])) {
			fprintf(stderr, "Invalid CUDA device id \"%s\"\n",
			        current->data);
			exit(1);
		}
		cuda_gpu_id = atoi(current->data);
	} else
		cuda_gpu_id = 0;

	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (cuda_gpu_id < devices && devices > 0)
		cudaSetDevice(cuda_gpu_id);
	else {
		fprintf(stderr, "Invalid CUDA device id = %d\n", cuda_gpu_id);
		exit(1);
	}
}

void cuda_done(void)
{
#ifdef HAVE_NVML
	nvmlShutdown();
#endif
}

/* https://developer.nvidia.com/sites/default/files/akamai/cuda/files/CUDADownloads/NVML_cuda5/nvml.4.304.55.pdf */
#ifdef HAVE_NVML
void cuda_get_temp(unsigned int cuda_gpu_id, unsigned int *temp,
                   unsigned int *fanspeed, unsigned int *util)
{
	nvmlUtilization_t s_util;
	nvmlDevice_t dev;
	nvmlReturn_t ret;

	ret = nvmlDeviceGetHandleByIndex(cuda_gpu_id, &dev);
	if (ret != NVML_SUCCESS)
	{
		*temp = *fanspeed = *util = 999;
		printf("returned %d\n", ret);
		return;
	}

	if (nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, temp) != NVML_SUCCESS)
		*temp = 999;
	if (nvmlDeviceGetFanSpeed(dev, fanspeed) != NVML_SUCCESS)
		*fanspeed = 999;
	if (nvmlDeviceGetUtilizationRates(dev, &s_util) == NVML_SUCCESS)
		*util = s_util.gpu;
	else
		*util = 999;
}
#endif
