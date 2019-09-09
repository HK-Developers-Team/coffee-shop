import React, { useState } from "react";
import {
  Col,
  Row,
  Carousel,
  CarouselItem,
  CarouselControl,
  CarouselIndicators,
  CarouselCaption
} from "reactstrap";

const HomePage = () => {
  return (
    <div>
      <Row>
        <Col xs={12} className="my-3">
          <Slide />
        </Col>
        <Col xs={12} md={8}>
          <h1>HomePage</h1>
        </Col>
        <Col xs={12} md={3}>
          <h1>SideBar</h1>
          <p>KyOcCho</p>
        </Col>
      </Row>
    </div>
  );
};

const Slide = () => {
  const [items, setItems] = useState([
    {
      src: "https://via.placeholder.com/1080x400?text=First%20Image",
      altText: "Slide 1",
      caption: "Slide 1",
    },
    {
      src: "https://via.placeholder.com/1080x400?text=Second%20Image",
      altText: "Slide 2",
      caption: "Slide 2",
    },
    {
      src: "https://via.placeholder.com/1080x400?text=Third%20Image",
      altText: "Slide 3",
      caption: "Slide 3",
    },
  ]);

  const [activeIndex, setActiveIndex] = useState(0);
  const [animating, setAnimating] = useState(false);

  const onExiting = () => {
    setAnimating(true);
  };

  const onExited = () => {
    setAnimating(false);
  };

  const next = () => {
    if (animating) return;
    const nextIndex = activeIndex === items.length - 1 ? 0 : activeIndex + 1;
    setActiveIndex(nextIndex);
  };

  const previous = () => {
    if (animating) return;
    const nextIndex = activeIndex === 0 ? items.length - 1 : activeIndex - 1;
    setActiveIndex(nextIndex);
  };

  const goToIndex = newIndex => {
    if (animating) return;
    setActiveIndex(newIndex);
  };

  const slides = items.map(item => {
    return (
      <CarouselItem onExiting={onExiting} onExited={onExited} key={item.src}>
        <img className="img-fluid" src={item.src} alt={item.altText} />
        <CarouselCaption
          captionText={item.caption}
          captionHeader={item.caption}
        />
      </CarouselItem>
    );
  });

  return (
    <Carousel activeIndex={activeIndex} next={next} previous={previous}>
      <CarouselIndicators
        items={items}
        activeIndex={activeIndex}
        onClickHandler={goToIndex}
      />
      {slides}
      <CarouselControl
        direction="prev"
        directionText="Previous"
        onClickHandler={previous}
      />
      <CarouselControl
        direction="next"
        directionText="Next"
        onClickHandler={next}
      />
    </Carousel>
  );
};

export default HomePage;
