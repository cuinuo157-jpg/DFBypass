include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DeltaForceBypass

DeltaForceBypass_FILES = Tweak.x
DeltaForceBypass_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
DeltaForceBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
