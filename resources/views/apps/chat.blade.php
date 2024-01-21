<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}

        <div class="flex lg:space-x-5 chat-height overflow-hidden relative rtl:space-x-reverse">
            <div class="chat-contact-bar">
                <div class="h-full card">
                    <div class="card-body relative p-0 h-full overflow-hidden">
                        <div class="border-b border-slate-100 dark:border-slate-700 pb-4">
                            <x-chat.profile />
                        </div>
                        <!-- end profile -->
                        <div class="border-b border-slate-100 dark:border-slate-700 py-1">
                            <div class="search px-3 mx-6 rounded flex items-center space-x-3 rtl:space-x-reverse">
                                <div class="flex-none text-base text-slate-900 dark:text-slate-400">
                                    <iconify-icon icon="bytesize:search"></iconify-icon>
                                </div>
                                <input placeholder="Search..." class="w-full flex-1 block bg-transparent placeholder:font-normal placeholder:text-slate-400 py-2 focus:ring-0
                  focus:outline-none dark:text-slate-200 dark:placeholder:text-slate-400">
                            </div>
                        </div>
                        <!-- end seach -->
                        <div class="contact-height" data-simplebar="data-simplebar">
                            <x-chat.contact />
                        </div>
                        <!-- end contact -->
                    </div>
                </div>
            </div>
            <div class="chat-overlay"></div>
            <!-- main chat box -->
            <div class="flex-1">
                <div class="parent flex space-x-5 h-full rtl:space-x-reverse">
                    <!-- end main message body -->
                    <div class="flex-1">
                        <div class="h-full card">
                            <div class="p-0 h-full body-class">
                                <x-chat.blank />
                                <x-chat.message />
                            </div>
                        </div>
                    </div>
                    <!-- right info bar -->
                    <div class="flex-none w-[285px]" id="info-box">
                        <div class="h-full card">
                            <div class="p-0 h-full card-body">
                                <x-chat.info />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/custom/app-chat.js'])
    @endpush
</x-app-layout>
