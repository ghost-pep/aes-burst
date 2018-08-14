#include "OpenCLRunner.h"

void brute_open_cl_cbc(vector<raw_pair*>* vec_keys, vector<raw_pair*>* vec_samples) {
	//set up host memory
	//TODO: convert the raw_pairs into something that can be used by the internals of OpenCL

	// set up the device memory
	cl::Buffer d_keys;                        // device memory used for the input  a vector */
    cl::Buffer d_ciphertexts;                        // device memory used for the input  b vector */
    cl::Buffer d_candidates;                       // device memory used for the output c vector */


    try 
    {
    	// Create a context
        cl::Context context(DEVICE);

        // Load in kernel source, creating a program object for the context

        cl::Program program(context, util::loadProgram("./OpenCL/brute_aes.cl"), true);

        // Get the command queue
        cl::CommandQueue cmd_queue(context);

        // Create the kernel functor
 
		//TODO: fill these values with the correct parameters to the brute_aes kernel
        auto brute_aes = cl::make_kernel<cl::Buffer, cl::Buffer, cl::Buffer, int>(program, "brute_aes");

        /* d_a   = cl::Buffer(context, begin(h_a), end(h_a), true); */
        /* d_b   = cl::Buffer(context, begin(h_b), end(h_b), true); */

        /* d_c  = cl::Buffer(context, CL_MEM_WRITE_ONLY, sizeof(float) * LENGTH); */

        /* util::Timer timer; */

    /*     vadd( */
    /*         cl::EnqueueArgs( */
    /*             queue, */
    /*             cl::NDRange(count)), */ 
    /*         d_a, */
    /*         d_b, */
    /*         d_c, */
    /*         count); */

    /*     queue.finish(); */

    /*     double rtime = static_cast<double>(timer.getTimeMilliseconds()) / 1000.0; */
    /*     printf("\nThe kernels ran in %lf seconds\n", rtime); */

    /*     cl::copy(queue, d_c, begin(h_c), end(h_c)); */

    /*     // Test the results */
    /*     int correct = 0; */
    /*     float tmp; */
    /*     for(int i = 0; i < count; i++) { */
    /*         tmp = h_a[i] + h_b[i]; // expected value for d_c[i] */
    /*         tmp -= h_c[i];                      // compute errors */
    /*         if(tmp*tmp < TOL*TOL) {      // correct if square deviation is less */ 
    /*             correct++;                         //  than tolerance squared */
    /*         } */
    /*         else { */

    /*             printf( */
    /*                 " tmp %f h_a %f h_b %f  h_c %f \n", */
    /*                 tmp, */ 
    /*                 h_a[i], */ 
    /*                 h_b[i], */ 
    /*                 h_c[i]); */
    /*         } */
    /*     } */

    /*     // summarize results */
    /*     printf( */
    /*         "vector add to find C = A+B:  %d out of %d results were correct.\n", */ 
    /*         correct, */ 
    /*         count); */
    }
    catch (cl::Error err) {
        std::cout << "Exception\n";
        std::cerr 
            << "ERROR: "
            << err.what()
            << "("
            << err_code(err.err())
           << ")"
           << std::endl;
    }
}
