#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h> 
#include <stdbool.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "utils.h"
#include "hookdata.h"
#include "dynamic.h"
#include "static.h"
#include "debugger.h"

static void usage()
{
    fprintf(stderr, 
        "Usage: sohook [OPTIONS] EXECUTABLE\n"
        "Inject dynamic library(.so) to target executable.\n"
        "\n"
        "Options:\n"
        "  -d, --dynamic        Enable dynamic mode.\n"
        "  -e, --embedded       Use dynamic library embedded hook info.\n"
        "  -h, --help           Display this information.\n"
        "  -m, --metadata       Hook data.\n"
        "  -s, --so             Dynamic library to be injected.\n"
    );
}

struct sohook_options
{
    bool dynamic;
    bool embedded;
    char* metadata;
    char* so;
    char* executable;
};

static struct sohook_options parse_arguments(int argc, char* argv[])
{
    struct sohook_options options = {0};

    static const struct option long_options[] =
    {
        {"dynamic", no_argument, 0, 'd'},
        {"embedded", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"metadata", required_argument, 0, 'm'},
        {"so", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    while (1)
    {
        int option_index;
        int c = getopt_long(argc, argv, "dehm:s:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
            case 'd':
                options.dynamic = true;
                break;
            case 'e':
                options.embedded = true;
                break;
            case 'm':
                options.metadata = optarg;
                break;
            case 's':
                options.so = optarg;
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "sohook: missing executable\n");
        usage();
        exit(EXIT_FAILURE);
    }

    options.executable = argv[optind];
    return options;
}

int main(int argc, char* argv[])
{
    struct sohook_options options = parse_arguments(argc, argv);
    
    if (options.so != NULL)
    {
        utils_assert(utils_check_file_available(options.so), "sohook: cannot read dynamic library %s\n", options.so);
        utils_assert(strlen(options.so) < 1024, "sohook: dynamic library path is too long\n");
    }

    if (options.executable != NULL)
        utils_assert(utils_check_file_available(options.executable), "sohook: cannot read executable %s\n", options.executable);

    // utils_assert(options.metadata || options.embedded, "sohook: missing hook data\n");
    // If no metadata is provided, try to use the embedded hook data.
    if (options.metadata == NULL)
        options.embedded = true;

    if (options.embedded)
        hookdata_load_elf(options.so);
    else
        hookdata_load_inj(options.metadata);
    
    hookdata_verify();

    struct debugger_context debugger = {0};
    debugger_init(&debugger, options.executable, options.so);

    if (options.dynamic)
        dynamic_main(&debugger);
    else
        static_main(&debugger);

    return 0;
}