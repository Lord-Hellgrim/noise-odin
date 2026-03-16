package internals


@(rodata)
PATTERN_XX : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee, .s, .es},
        {.s, .se}
    }
}
@(rodata)
PATTERN_NK : MessagePattern = {
    pre_messages = {.res_s},
    messages = {
        {.e, .es},
        {.e, .ee},
    }
}
@(rodata)
PATTERN_NN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .ee},
    }
}
@(rodata)
PATTERN_KN : MessagePattern = {
    pre_messages = {.ini_s},
    messages = {
        {.e,},
        {.e, .ee, .se}
    }
}
@(rodata)
PATTERN_KK : MessagePattern = {
    pre_messages = {.ini_s, .res_s},
    messages = {
        {.e, .es, .ss},
        {.e, .ee, .se},
    }
}
@(rodata)
PATTERN_NX : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee, .s, .es},
    }
}
@(rodata)
PATTERN_KX : MessagePattern = {
    pre_messages = {.ini_s},
    messages = {
        {.e},
        {.e, .ee, .se, .s, .es}
    }
}
@(rodata)
PATTERN_XN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee},
        {.s, .se},
    }
}
@(rodata)
PATTERN_IN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .s},
        {.e, .ee, .se},
    }
}
@(rodata)
PATTERN_XK : MessagePattern = {
    pre_messages = {.res_s},
    messages = {
        {.e, .es},
        {.e, .ee},
        {.s, .se},
    }
}
@(rodata)
PATTERN_IK : MessagePattern = {
    pre_messages = {.res_s}, 
    messages = {
        {.e, .es, .s, .ss},
        {.e, .ee, .se}
    }
}
@(rodata)
PATTERN_IX :  MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .s},
        {.e, .ee, .se, .s, .es},
    }
}