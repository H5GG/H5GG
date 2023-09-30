//
//  globalview.h
//  h5gg
//
//  Created by admin on 25/4/2022.
//

#ifndef globalview_h
#define globalview_h

typedef struct {
    BOOL enable;
    BOOL appLoaded;
    BOOL viewHosted;
    BOOL touchableAll;
    CGRect touchableRect;
    CGRect floatMenuRect;
    BOOL floatBtnClick;
    BOOL customButtonAction;
    BOOL followCurrentOrientation;
    UIInterfaceOrientation curOrientation;
    BOOL setWindowVisible;
    BOOL windowVisibleState;
    size_t buttonImageSize;
    Byte buttonImageData[512*1024];
} GVData;

static GVData GVDataDefault = {NO, NO, NO, YES, CGRectZero, CGRectZero, NO, NO, NO, (UIInterfaceOrientation)0, NO, NO, 0};

#endif /* globalview_h */
