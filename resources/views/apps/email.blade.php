<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}


        <div class="flex md:space-x-5 app_height overflow-hidden relative rtl:space-x-reverse">
            <div class="email-sidebar ">
                <div class="h-full card">
                    <div class="card-body py-6 h-full flex flex-col">
                        <div class="flex-1 h-full px-6">
                            <button class="btn inline-flex justify-center btn-dark w-full" data-bs-toggle="modal" data-bs-target="#newEmailModal">
                                <span class="flex items-center">
                                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="ph:plus-bold"></iconify-icon>
                                    <span>Compose</span>
                                </span>
                            </button>
                        </div>
                        <div class="h-full px-6 " data-simplebar="data-simplebar">
                            <ul class="email-categories list mt-6">
                                <x-email.topfilter />
                            </ul>
                            <div class="block py-4 text-slate-800 dark:text-slate-400 font-semibold text-xs uppercase">
                                Tags
                            </div>
                            <ul class="email-categories list">
                                <ul class="email-categories list">
                                    <x-email.bottomfilter />
                                </ul>
                        </div>
                    </div>
                </div>
            </div>
            <div class="email-overlay"></div>
            <div class="flex-1 md:w-[calc(100%-320px)]">
                <div class="h-full card">
                    <div class="p-0  h-full relative card-body">
                        <x-email.email-header />
                        <div class="h-full all-todos overflow-x-hidden" data-simplebar="data-simplebar">
                            <ul class="divide-y divide-slate-100 dark:divide-slate-700 -mb-6 h-full email-list">
                                <x-email.emails />
                                <x-email.no-result />
                            </ul>
                        </div>
                        <x-email.single-email />
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="newEmailModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col lg:w-[576px] w-full pointer-events-auto bg-white
          bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-slate-900 dark:bg-slate-700">
                            <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                Compose Email
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                    11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <form class="flex flex-col space-y-3">
                                <div class="input-area">
                                    <label for="email" class="form-label">To</label>
                                    <input id="email" type="text" class="form-control" placeholder="Email">
                                </div>
                                <div class="input-area">
                                    <label for="subject" class="form-label">Subject</label>
                                    <input id="subject" type="text" class="form-control" placeholder="Enter Title">
                                </div>
                                <div class="!mt-7 rounded">
                                    <div id="editor-container" class="h-32 dark:text-white"></div>
                                </div>
                                <div class="flex items-center justify-end rounded-b dark:border-slate-600">
                                    <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Send</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
    @vite(['resources/js/custom/app-email.js'])
    @endpush
</x-app-layout>